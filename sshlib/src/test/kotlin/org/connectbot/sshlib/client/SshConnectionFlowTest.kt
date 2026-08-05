/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot.sshlib.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.connectbot.sshlib.AgentIdentity
import org.connectbot.sshlib.AgentKeySpec
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AgentResult
import org.connectbot.sshlib.AgentSigningContext
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.DestinationConstraint
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SessionExit
import org.connectbot.sshlib.crypto.PrivateKeyReader
import org.connectbot.sshlib.crypto.SshPublicKeyEncoder
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class SshConnectionFlowTest {

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    @Test
    fun `unsolicited authentication success is rejected as a protocol error`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val disconnected = async(dispatcher) { connection.disconnectedFlow.first() }
            server.sendUserauthSuccess()

            val failure = assertNotNull(withTimeout(5_000) { disconnected.await() })
            assertTrue(failure.message.orEmpty().contains("Unexpected SSH packet SSH_MSG_USERAUTH_SUCCESS"))
        }
    }

    @Test
    fun `wrong direction packet receives unimplemented without advancing state`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            server.sendUnknownPacket()
            val unknownReply = withTimeout(5_000) { server.awaitUnimplemented() }

            server.sendUnexpectedServiceRequest()
            val wrongDirectionReply = withTimeout(5_000) { server.awaitUnimplemented() }
            assertEquals(unknownReply.packetSequence() + 1, wrongDirectionReply.packetSequence())

            val authentication = async(dispatcher) { connection.authenticatePassword("user", "pass") }
            withTimeout(5_000) { server.awaitUserauthRequest() }
            server.sendUserauthSuccess()
            assertEquals(AuthResult.Success, withTimeout(5_000) { authentication.await() })
        }
    }

    @Test
    fun `duplicate kex init during rekey is a fatal protocol error`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val disconnected = async(dispatcher) { connection.disconnectedFlow.first() }
            server.sendDuplicateKexInitDuringRekey = true
            server.initiateRekey()

            val failure = assertNotNull(withTimeout(5_000) { disconnected.await() })
            assertTrue(failure.message.orEmpty().contains("Unexpected SSH_MSG_KEXINIT"))
        }
    }

    @Test
    fun `connect returns host key rejected when verifier rejects server key`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start(ignoreTransportErrors = true)

        val rejectingVerifier = object : HostKeyVerifier {
            override suspend fun verify(key: PublicKey): Boolean = false
        }
        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = rejectingVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            assertIs<ConnectResult.HostKeyRejected>(connectInBackground(connection, backgroundScope, dispatcher))
        } finally {
            connection.close()
        }
    }

    @Test
    fun `host key verifier is not called before server proves key possession`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher).apply {
            corruptKexSignature = true
        }
        server.start(ignoreTransportErrors = true)
        var verifierCalled = false
        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean {
                    verifierCalled = true
                    return true
                }
            },
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertFalse(result is ConnectResult.Success)
            assertFalse(verifierCalled)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `connect returns algorithm mismatch when kex negotiation has no match`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.kexAlgorithms = "unsupported-kex@example.com"
        server.start(ignoreTransportErrors = true)

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            assertIs<ConnectResult.AlgorithmMismatch>(connectInBackground(connection, backgroundScope, dispatcher))
        } finally {
            connection.close()
        }
    }

    @Test
    fun `password authentication handles success and failure replies`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val success = async(dispatcher) { connection.authenticatePassword("user", "pass") }
            val successRequest = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("password", successRequest.methodName().value())
            server.sendUserauthSuccess()
            assertEquals(AuthResult.Success, withTimeout(5_000) { success.await() })
        }

        connectedFixture { connection, server, dispatcher ->
            val failure = async(dispatcher) { connection.authenticatePassword("user", "bad") }
            val failureRequest = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("password", failureRequest.methodName().value())
            server.sendUserauthFailure(setOf("publickey", "keyboard-interactive"), partialSuccess = false)

            assertIs<AuthResult.Failure>(withTimeout(5_000) { failure.await() })
        }
    }

    @Test
    fun `public key authentication signs and handles success reply`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val privateKeyData = Files.readString(Paths.get("src/test/resources/keys/ed25519_unencrypted"))
            val privateKey = PrivateKeyReader.read(privateKeyData)

            val auth = async(dispatcher) { connection.authenticatePublicKey("user", privateKey) }
            val request = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("publickey", request.methodName().value())
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `public key authentication handles failure reply`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val privateKeyData = Files.readString(Paths.get("src/test/resources/keys/ed25519_unencrypted"))
            val privateKey = PrivateKeyReader.read(privateKeyData)

            val auth = async(dispatcher) { connection.authenticatePublicKey("user", privateKey) }
            val request = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("publickey", request.methodName().value())
            server.sendUserauthFailure(setOf("password"), partialSuccess = false)

            assertIs<AuthResult.Failure>(withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `direct keyboard interactive authentication handles info request`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val callback = object : KeyboardInteractiveCallback {
                override suspend fun onInfoRequest(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                    respond: suspend (responses: List<String>) -> Unit,
                ) {
                    assertEquals("login", name)
                    assertEquals("challenge", prompts.single().text)
                    respond(listOf("answer"))
                }
            }

            val auth = async(dispatcher) { connection.authenticateKeyboardInteractive("user", callback) }
            val request = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("keyboard-interactive", request.methodName().value())

            server.sendUserauthInfoRequest("login", "instruction", listOf("challenge" to false))
            yield()
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `strategy authentication succeeds when none auth is accepted`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val auth = async(dispatcher) { connection.authenticate("user", EmptyAuthHandler()) }
            val none = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("none", none.methodName().value())
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `strategy authentication delivers banners while discovering methods`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val banners = mutableListOf<String>()
            val observedMethods = mutableListOf<Set<String>>()
            val handler = object : EmptyAuthHandler() {
                override suspend fun onAuthMethodsAvailable(methods: Set<String>) {
                    observedMethods.add(methods)
                }

                override suspend fun onPasswordNeeded(): String = "secret"

                override suspend fun onBanner(message: String) {
                    banners.add(message)
                }
            }

            val auth = async(dispatcher) { connection.authenticate("user", handler) }
            assertEquals("none", withTimeout(5_000) { server.awaitUserauthRequest() }.methodName().value())
            server.sendUserauthBanner("maintenance window")
            server.sendUserauthFailure(setOf("password"), partialSuccess = false)

            assertEquals("password", withTimeout(5_000) { server.awaitUserauthRequest() }.methodName().value())
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
            assertEquals(listOf("maintenance window"), banners)
            assertEquals(listOf(setOf("password")), observedMethods)
        }
    }

    @Test
    fun `strategy authentication discovers methods and succeeds with password`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val handler = object : EmptyAuthHandler() {
                override suspend fun onPasswordNeeded(): String = "secret"
            }

            val auth = async(dispatcher) { connection.authenticate("user", handler) }
            val none = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("none", none.methodName().value())
            server.sendUserauthFailure(setOf("password"), partialSuccess = false)

            val password = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("password", password.methodName().value())
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `strategy authentication fails when password is unavailable`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val auth = async(dispatcher) { connection.authenticate("user", EmptyAuthHandler()) }
            assertEquals("none", withTimeout(5_000) { server.awaitUserauthRequest() }.methodName().value())
            server.sendUserauthFailure(setOf("password"), partialSuccess = false)

            assertIs<AuthResult.Failure>(withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `strategy authentication handles keyboard interactive prompt`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val handler = object : EmptyAuthHandler() {
                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String> {
                    assertEquals("login", name)
                    assertEquals("answer", prompts.single().text)
                    return listOf("response")
                }
            }

            val auth = async(dispatcher) { connection.authenticate("user", handler) }
            assertEquals("none", withTimeout(5_000) { server.awaitUserauthRequest() }.methodName().value())
            server.sendUserauthFailure(setOf("keyboard-interactive"), partialSuccess = false)

            assertEquals("keyboard-interactive", withTimeout(5_000) { server.awaitUserauthRequest() }.methodName().value())
            server.sendUserauthInfoRequest("login", "instruction", listOf("answer" to false))
            yield()
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `strategy authentication probes and signs accepted public key`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            val privateKeyData = Files.readString(Paths.get("src/test/resources/keys/ed25519_unencrypted"))
            val privateKey = PrivateKeyReader.read(privateKeyData)
            val publicKeyBlob = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)
            val authKey = AuthPublicKey(privateKey.signatureAlgorithm, publicKeyBlob)
            val handler = object : EmptyAuthHandler() {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = listOf(authKey)
                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray = byteArrayOf(1, 2, 3)
            }

            val auth = async(dispatcher) { connection.authenticate("user", handler) }
            assertEquals("none", withTimeout(5_000) { server.awaitUserauthRequest() }.methodName().value())
            server.sendUserauthFailure(setOf("publickey"), partialSuccess = false)

            val probe = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("publickey", probe.methodName().value())
            server.sendUserauthPkOk(authKey.algorithmName, authKey.publicKeyBlob)

            val signed = withTimeout(5_000) { server.awaitUserauthRequest() }
            assertEquals("publickey", signed.methodName().value())
            server.sendUserauthSuccess()

            assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
        }
    }

    @Test
    fun `session channel open handles confirmation request success and failure`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            val open = async(dispatcher) { connection.openSessionChannel() }
            val openRequest = withTimeout(5_000) { server.awaitChannelOpen() }
            assertEquals("session", openRequest.channelType().value())
            server.sendChannelOpenConfirmation(openRequest.senderChannel().toInt(), senderChannel = 100)

            val session = assertNotNull(withTimeout(5_000) { open.await() })

            val exec = async(dispatcher) { session.requestExec("true") }
            val request = withTimeout(5_000) { server.awaitChannelRequest() }
            assertEquals("exec", request.requestType().value())
            server.sendChannelSuccess(session.localChannelNumber)
            assertTrue(withTimeout(5_000) { exec.await() })

            val shell = async(dispatcher) { session.requestShell() }
            val shellRequest = withTimeout(5_000) { server.awaitChannelRequest() }
            assertEquals("shell", shellRequest.requestType().value())
            server.sendChannelFailure(session.localChannelNumber)
            assertEquals(false, withTimeout(5_000) { shell.await() })
        }
    }

    @Test
    fun `session channel open returns null on open failure`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            val open = async(dispatcher) { connection.openSessionChannel() }
            val openRequest = withTimeout(5_000) { server.awaitChannelOpen() }
            server.sendChannelOpenFailure(openRequest.senderChannel().toInt())

            assertNull(withTimeout(5_000) { open.await() })
        }
    }

    @Test
    fun `session channel routes data extended data eof and close`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelData(localChannel, byteArrayOf(1, 2, 3))
            assertContentEquals(byteArrayOf(1, 2, 3), withTimeout(5_000) { session.stdout.receive() })

            server.sendChannelExtendedData(localChannel, 1, byteArrayOf(4, 5))
            val stderr = withTimeout(5_000) { session.stderr.receive() }
            assertContentEquals(byteArrayOf(4, 5), stderr)

            server.sendChannelWindowAdjust(localChannel, 1024)
            server.sendChannelEof(localChannel)
            assertNull(withTimeout(5_000) { session.read() })

            server.sendChannelClose(localChannel)
            withTimeout(5_000) {
                while (session.isOpen) {
                    yield()
                }
            }
        }
    }

    @Test
    fun `session channel preserves data received before close until consumer reads`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            connection.autoDisconnectOnLastChannelClose = false
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelData(localChannel, byteArrayOf(1, 2, 3))
            server.sendChannelExtendedData(localChannel, 1, byteArrayOf(4, 5))
            server.sendChannelExtendedData(localChannel, 7, byteArrayOf(6, 7))
            server.sendChannelClose(localChannel)
            withTimeout(5_000) {
                while (session.isOpen) yield()
            }

            assertContentEquals(byteArrayOf(1, 2, 3), withTimeout(5_000) { session.stdout.receive() })
            assertContentEquals(byteArrayOf(4, 5), withTimeout(5_000) { session.stderr.receive() })
            val extended = withTimeout(5_000) { session.readExtended() }
            assertEquals(7, extended?.first)
            assertContentEquals(byteArrayOf(6, 7), extended?.second)
            assertNull(withTimeout(5_000) { session.read() })
            assertNull(withTimeout(5_000) { session.stderr.receiveCatching().getOrNull() })
            assertNull(withTimeout(5_000) { session.readExtended() })
        }
    }

    @Test
    fun `session channel preserves a multi-window stdout tail when close follows data`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            connection.autoDisconnectOnLastChannelClose = false
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber
            val packetSize = 32 * 1024
            val expected = ByteArray(1024 * 1024) { index -> (index % 251).toByte() }
            val tailReceiverBlocked = CompletableDeferred<Unit>()
            val releaseTailReceiver = CompletableDeferred<Unit>()
            val received = async(dispatcher) {
                val output = ByteArrayOutputStream(expected.size)
                for (chunk in session.stdout) {
                    output.write(chunk)
                    if (output.size() == expected.size - packetSize) {
                        tailReceiverBlocked.complete(Unit)
                        releaseTailReceiver.await()
                    }
                    yield()
                }
                output.toByteArray()
            }

            var offset = 0
            var availableWindow = 64 * 1024L
            while (offset < expected.size) {
                if (availableWindow == 0L) {
                    val adjust = withTimeout(5_000) { server.awaitChannelWindowAdjust() }
                    assertEquals(100L, adjust.recipientChannel())
                    availableWindow += adjust.bytesToAdd()
                }
                val chunkSize = minOf(packetSize.toLong(), availableWindow, (expected.size - offset).toLong()).toInt()
                server.sendChannelData(localChannel, expected.copyOfRange(offset, offset + chunkSize))
                offset += chunkSize
                availableWindow -= chunkSize
            }
            server.sendChannelClose(localChannel)

            withTimeout(5_000) {
                while (session.isOpen) yield()
            }
            assertTrue(tailReceiverBlocked.isCompleted)
            releaseTailReceiver.complete(Unit)
            assertContentEquals(expected, withTimeout(5_000) { received.await() })
            assertNull(withTimeout(5_000) { session.read() })
        }
    }

    @Test
    fun `exit-status channel request completes exitInfo`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelExitStatus(localChannel, 42L)
            assertEquals(
                SessionExit.Status(42L),
                withTimeout(5_000) { session.exitInfo.await() },
            )
        }
    }

    @Test
    fun `exit-status supports max uint32 boundary condition`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelExitStatus(localChannel, 0xFFFF_FFFFL)
            assertEquals(
                SessionExit.Status(0xFFFF_FFFFL),
                withTimeout(5_000) { session.exitInfo.await() },
            )
        }
    }

    @Test
    fun `exit-signal channel request completes exitInfo`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelExitSignal(localChannel, "KILL", coreDumped = true, errorMessage = "killed")
            assertEquals(
                SessionExit.Signal("KILL", coreDumped = true, errorMessage = "killed"),
                withTimeout(5_000) { session.exitInfo.await() },
            )
        }
    }

    @Test
    fun `exitInfo resolves null when the channel closes without an exit report`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelEof(localChannel)
            server.sendChannelClose(localChannel)
            assertNull(withTimeout(5_000) { session.exitInfo.await() })
        }
    }

    @Test
    fun `first exit report wins over a later one`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)
            val session = openSession(connection, server, dispatcher)
            val localChannel = session.localChannelNumber

            server.sendChannelExitStatus(localChannel, 7L)
            server.sendChannelExitSignal(localChannel, "TERM")
            server.sendChannelClose(localChannel)
            assertEquals(
                SessionExit.Status(7L),
                withTimeout(5_000) { session.exitInfo.await() },
            )
        }
    }

    @Test
    fun `opening a second session channel after closing the first succeeds when server reuses remote channel number`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            connection.autoDisconnectOnLastChannelClose = false
            authenticate(connection, server, dispatcher)

            val session1 = openSession(connection, server, dispatcher, remoteChannelNumber = 100)
            val localChannel1 = session1.localChannelNumber

            server.sendChannelClose(localChannel1)
            withTimeout(5_000) {
                while (session1.isOpen) {
                    yield()
                }
            }

            val session2 = openSession(connection, server, dispatcher, remoteChannelNumber = 100)
            assertTrue(session2.isOpen)
        }
    }

    @Test
    fun `direct tcpip channel routes data eof and close`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            val open = async(dispatcher) {
                connection.openDirectTcpipChannel("target", 22, "127.0.0.1", 12345)
            }
            val openRequest = withTimeout(5_000) { server.awaitChannelOpen() }
            assertEquals("direct-tcpip", openRequest.channelType().value())
            server.sendChannelOpenConfirmation(openRequest.senderChannel().toInt(), senderChannel = 200)
            val channel = assertNotNull(withTimeout(5_000) { open.await() })

            server.sendChannelData(channel.localChannelNumber, byteArrayOf(9, 8))
            assertContentEquals(byteArrayOf(9, 8), withTimeout(5_000) { channel.incomingData.receive() })

            server.sendChannelWindowAdjust(channel.localChannelNumber, 1024)
            server.sendChannelEof(channel.localChannelNumber)
            assertNull(withTimeout(5_000) { channel.incomingData.receiveCatching().getOrNull() })

            server.sendChannelClose(channel.localChannelNumber)
            withTimeout(5_000) {
                while (channel.isOpen) {
                    yield()
                }
            }
        }
    }

    @Test
    fun `direct tcpip channel preserves data received before close until consumer reads`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            val open = async(dispatcher) {
                connection.openDirectTcpipChannel("target", 22, "127.0.0.1", 12345)
            }
            val openRequest = withTimeout(5_000) { server.awaitChannelOpen() }
            server.sendChannelOpenConfirmation(openRequest.senderChannel().toInt(), senderChannel = 200)
            val channel = assertNotNull(withTimeout(5_000) { open.await() })

            server.sendChannelData(channel.localChannelNumber, byteArrayOf(9, 8, 7))
            server.sendChannelClose(channel.localChannelNumber)
            withTimeout(5_000) {
                while (channel.isOpen) yield()
            }

            assertContentEquals(
                byteArrayOf(9, 8, 7),
                withTimeout(5_000) { channel.incomingData.receive() },
            )
            assertNull(withTimeout(5_000) { channel.incomingData.receiveCatching().getOrNull() })
        }
    }

    @Test
    fun `incoming agent channel is rejected without provider and accepted with provider`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            server.sendChannelOpen("unknown-channel-type", senderChannel = 76)
            val unknownFailure = withTimeout(5_000) { server.awaitChannelOpenFailure() }
            assertEquals(76, unknownFailure.recipientChannel().toInt())

            server.sendChannelOpen("auth-agent@openssh.com", senderChannel = 77)
            val failure = withTimeout(5_000) { server.awaitChannelOpenFailure() }
            assertEquals(77, failure.recipientChannel().toInt())

            connection.enableAgentForwarding(
                object : AgentProvider {
                    override suspend fun getIdentities() = AgentResult.Success(emptyList<AgentIdentity>())
                    override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
                },
            )

            server.sendChannelOpen("auth-agent@openssh.com", senderChannel = 78)
            val confirmation = withTimeout(5_000) { server.awaitChannelOpenConfirmation() }
            assertEquals(78, confirmation.recipientChannel().toInt())

            val agentLocalChannel = confirmation.senderChannel().toInt()
            server.sendChannelData(agentLocalChannel, ByteBuffer.allocate(5).putInt(1).put(11).array())
            server.sendChannelWindowAdjust(agentLocalChannel, 1024)
            server.sendChannelEof(agentLocalChannel)
            server.sendChannelClose(agentLocalChannel)
            yield()
        }
    }

    @Test
    fun `incoming agent channel starts with the verified connection binding`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            val currentHostKey = server.serverHostKeyBlob
            val nextHostKey = byteArrayOf(9, 8, 7)
            val constrainedIdentity = AgentIdentity(
                publicKeyBlob = byteArrayOf(1, 2, 3),
                comment = "constrained",
                destinationConstraints = listOf(
                    DestinationConstraint(
                        fromHostname = "",
                        fromKeyspecs = emptyList(),
                        toUsername = "",
                        toHostname = "current",
                        toHostspecs = listOf(AgentKeySpec(currentHostKey, isCa = false)),
                    ),
                    DestinationConstraint(
                        fromHostname = "current",
                        fromKeyspecs = listOf(AgentKeySpec(currentHostKey, isCa = false)),
                        toUsername = "",
                        toHostname = "next",
                        toHostspecs = listOf(AgentKeySpec(nextHostKey, isCa = false)),
                    ),
                ),
            )
            connection.enableAgentForwarding(
                object : AgentProvider {
                    override suspend fun getIdentities() = AgentResult.Success(listOf(constrainedIdentity))
                    override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
                },
            )

            server.sendChannelOpen("auth-agent@openssh.com", senderChannel = 79)
            val confirmation = withTimeout(5_000) { server.awaitChannelOpenConfirmation() }
            val agentLocalChannel = confirmation.senderChannel().toInt()
            server.sendChannelData(agentLocalChannel, ByteBuffer.allocate(5).putInt(1).put(11).array())

            val responsePacket = withTimeout(5_000) { server.awaitChannelData() }
            assertEquals(79, responsePacket.recipientChannel().toInt())
            val response = ByteBuffer.wrap(responsePacket.data().data())
            assertEquals(12, response.get(4).toInt() and 0xFF)
            assertEquals(1, response.getInt(5))

            server.sendChannelClose(agentLocalChannel)
            yield()
        }
    }

    @Test
    fun `tcpip forward request handles assigned port success fixed port success and failure`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            val assigned = async(dispatcher) { connection.sendTcpipForwardRequest("127.0.0.1", 0) }
            yield()
            server.sendRequestSuccess(ByteBuffer.allocate(4).putInt(9022).array())
            assertEquals(9022, withTimeout(5_000) { assigned.await() })

            val fixed = async(dispatcher) { connection.sendTcpipForwardRequest("127.0.0.1", 2022) }
            yield()
            server.sendRequestSuccess()
            assertEquals(2022, withTimeout(5_000) { fixed.await() })

            val rejected = async(dispatcher) { connection.sendTcpipForwardRequest("127.0.0.1", 3022) }
            yield()
            server.sendRequestFailure()
            assertNull(withTimeout(5_000) { rejected.await() })

            connection.sendCancelTcpipForward("127.0.0.1", 2022)
        }
    }

    @Test
    fun `server disconnect is emitted on disconnected flow`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            server.sendDisconnect("finished")

            withTimeout(5_000) { connection.disconnectedFlow.first() }
        }
    }

    @Test
    fun `unhandled global request with want reply is rejected`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            server.sendGlobalRequest("keepalive@example.com", wantReply = true)
            yield()
        }
    }

    @Test
    fun `unexpected pong payloads are ignored`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            server.sendServerPong(byteArrayOf(1, 2, 3))
            server.sendServerPong(ByteBuffer.allocate(8).putLong(999).array())
            yield()
        }
    }

    @Test
    fun `incoming forwarded tcpip channel rejects missing handler and invokes registered handler`() = runTest {
        connectedFixture { connection, server, dispatcher ->
            authenticate(connection, server, dispatcher)

            server.sendForwardedTcpipChannelOpen(
                senderChannel = 88,
                connectedAddress = "127.0.0.1",
                connectedPort = 8022,
                originatorAddress = "10.0.0.1",
                originatorPort = 50000,
            )
            val failure = withTimeout(5_000) { server.awaitChannelOpenFailure() }
            assertEquals(88, failure.recipientChannel().toInt())

            val forwarded = CompletableDeferred<List<Any>>()
            connection.registerRemoteForwarder("127.0.0.1:8022") { connectedAddr, connectedPort, originAddr, originPort, senderChannel, initialWindow, maxPacketSize ->
                forwarded.complete(listOf(connectedAddr, connectedPort, originAddr, originPort, senderChannel, initialWindow, maxPacketSize))
            }

            server.sendForwardedTcpipChannelOpen(
                senderChannel = 89,
                connectedAddress = "127.0.0.1",
                connectedPort = 8022,
                originatorAddress = "10.0.0.2",
                originatorPort = 50001,
            )

            assertEquals(
                listOf("127.0.0.1", 8022, "10.0.0.2", 50001, 89, 65536L, 32768),
                withTimeout(5_000) { forwarded.await() },
            )
        }
    }

    private suspend fun authenticate(
        connection: SshConnection,
        server: FakeSshServer,
        dispatcher: CoroutineDispatcher,
    ) {
        val auth = CoroutineScope(dispatcher).async { connection.authenticatePassword("user", "pass") }
        withTimeout(5_000) { server.awaitUserauthRequest() }
        server.sendUserauthSuccess()
        assertEquals(AuthResult.Success, withTimeout(5_000) { auth.await() })
    }

    private suspend fun openSession(
        connection: SshConnection,
        server: FakeSshServer,
        dispatcher: CoroutineDispatcher,
        remoteChannelNumber: Int = 100,
    ): SessionChannel {
        val open = CoroutineScope(dispatcher).async { connection.openSessionChannel() }
        val openRequest = withTimeout(5_000) { server.awaitChannelOpen() }
        assertEquals("session", openRequest.channelType().value())
        server.sendChannelOpenConfirmation(openRequest.senderChannel().toInt(), senderChannel = remoteChannelNumber)
        return assertNotNull(withTimeout(5_000) { open.await() })
    }

    private open class EmptyAuthHandler : AuthHandler {
        override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()
        override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null
        override suspend fun onKeyboardInteractivePrompt(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
        ): List<String>? = null
        override suspend fun onPasswordNeeded(): String? = null
    }

    private suspend fun TestScope.connectedFixture(
        block: suspend (SshConnection, FakeSshServer, CoroutineDispatcher) -> Unit,
    ) {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )

        try {
            val connectResult = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(connectResult)
            val info = assertNotNull(connection.connectionInfo)
            assertEquals("curve25519-sha256", info.kexAlgorithm)
            assertEquals("ssh-ed25519", info.serverHostKeyAlgorithm)
            assertEquals("aes128-ctr", info.encryptionAlgorithmC2S)
            assertEquals("aes128-ctr", info.encryptionAlgorithmS2C)
            block(connection, server, dispatcher)
        } finally {
            connection.close()
        }
    }

    private suspend fun connectInBackground(
        connection: SshConnection,
        scope: CoroutineScope,
        dispatcher: CoroutineDispatcher,
    ): ConnectResult {
        val result = CompletableDeferred<ConnectResult>()
        scope.launch(dispatcher) { result.complete(connection.connect()) }
        yield()
        return result.await()
    }
}
