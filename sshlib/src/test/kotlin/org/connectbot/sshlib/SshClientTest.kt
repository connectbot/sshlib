/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

package org.connectbot.sshlib

import io.ktor.utils.io.ByteChannel
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import nl.jqno.equalsverifier.EqualsVerifier
import org.connectbot.sshlib.client.ForwardingChannel
import org.connectbot.sshlib.client.SessionChannel
import org.connectbot.sshlib.client.SshConnection
import org.connectbot.sshlib.crypto.SshPrivateKey
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SshClientTest {
    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun clientWithHost(host: String): SshClient {
        val config = SshClientConfig {
            this.host = host
            this.hostKeyVerifier = acceptAllVerifier
        }
        return SshClient(config)
    }

    private val mockKeyboardInteractiveCallback = object : KeyboardInteractiveCallback {
        override suspend fun onInfoRequest(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
            respond: suspend (responses: List<String>) -> Unit,
        ) {
            respond(emptyList())
        }
    }

    private val mockAuthHandler = object : AuthHandler {
        override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()
        override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null
        override suspend fun onKeyboardInteractivePrompt(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
        ): List<String>? = emptyList()
        override suspend fun onPasswordNeeded(): String? = null
    }

    @Test
    fun `AuthPublicKey equals and hashCode`() {
        EqualsVerifier.forClass(AuthPublicKey::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }

    @Test
    fun `connect returns TransportError when factory fails`() = runTest {
        val config = SshClientConfig {
            this.transportFactory = TransportFactory { throw Exception("fail") }
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        val result = client.connect()
        assertIs<ConnectResult.TransportError>(result)
    }

    @Test
    fun `host factory overload accepts host verifier`() {
        SshClient("example.com", hostKeyVerifier = acceptAllVerifier)
    }

    @Test
    fun `transport factory overload accepts host verifier`() {
        SshClient(TransportFactory { throw Exception("unused") }, acceptAllVerifier)
    }

    @Test
    fun `openSession returns null when not connected`() = runTest {
        val client = clientWithHost("host")
        val session = client.openSession()
        assertNull(session)
    }

    @Test
    fun `authenticatePassword returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticatePassword("user", "pass")
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticateKeyboardInteractive returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticateKeyboardInteractive("user", mockKeyboardInteractiveCallback)
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticatePublicKey returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticatePublicKey("user", "keydata")
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticate returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticate("user", mockAuthHandler)
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticate wrappers set authenticated on success and preserve failures`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val client = connectedClient(connection)
        coEvery { connection.authenticatePassword("user", "pass") } returns AuthResult.Success
        coEvery { connection.authenticateKeyboardInteractive("user", mockKeyboardInteractiveCallback) } returns AuthResult.Failure(setOf("password"))
        coEvery { connection.authenticate("user", mockAuthHandler) } returns AuthResult.Success

        assertEquals(AuthResult.Success, client.authenticatePassword("user", "pass"))
        assertTrue(client.isAuthenticated)
        assertEquals(AuthResult.Failure(setOf("password")), client.authenticateKeyboardInteractive("user", mockKeyboardInteractiveCallback))
        assertEquals(AuthResult.Success, client.authenticate("user", mockAuthHandler))
    }

    @Test
    fun `authenticate wrappers convert connection exceptions to errors`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val client = connectedClient(connection)
        coEvery { connection.authenticatePassword(any(), any()) } throws IllegalStateException("password failed")
        coEvery { connection.authenticateKeyboardInteractive(any(), any()) } throws IllegalStateException("keyboard failed")
        coEvery { connection.authenticate(any(), any()) } throws IllegalStateException("handler failed")

        assertAuthError("password failed", client.authenticatePassword("user", "pass"))
        assertAuthError("keyboard failed", client.authenticateKeyboardInteractive("user", mockKeyboardInteractiveCallback))
        assertAuthError("handler failed", client.authenticate("user", mockAuthHandler))
    }

    @Test
    fun `authenticatePublicKey string and byte array overloads delegate parsed keys`() = runTest {
        val keyData = Files.readString(Paths.get("src/test/resources/keys/ed25519_unencrypted"))
        val connection = mockk<SshConnection>(relaxed = true)
        val client = connectedClient(connection)
        coEvery { connection.authenticatePublicKey(eq("user"), any<SshPrivateKey>()) } returns AuthResult.Success

        assertEquals(AuthResult.Success, client.authenticatePublicKey("user", keyData))
        assertTrue(client.isAuthenticated)
        assertEquals(AuthResult.Success, client.authenticatePublicKey("user", keyData.toByteArray()))

        coVerify(exactly = 2) { connection.authenticatePublicKey(eq("user"), any<SshPrivateKey>()) }
    }

    @Test
    fun `authenticatePublicKey preserves failures and maps parse errors`() = runTest {
        val keyData = Files.readString(Paths.get("src/test/resources/keys/ed25519_unencrypted"))
        val connection = mockk<SshConnection>(relaxed = true)
        val client = connectedClient(connection)
        val failure = AuthResult.Failure(setOf("password"))
        coEvery { connection.authenticatePublicKey(eq("user"), any<SshPrivateKey>()) } returns failure

        assertEquals(failure, client.authenticatePublicKey("user", keyData))
        assertFalse(client.isAuthenticated)
        assertIs<AuthResult.Error>(client.authenticatePublicKey("user", "not a private key"))
    }

    @Test
    fun `isPrivateKeyEncrypted handles invalid key data gracefully`() {
        val client = clientWithHost("host")
        // This should not throw but return false or log error
        client.isPrivateKeyEncrypted("invalid key data")
    }

    @Test
    fun `connectionInfo is null before connect`() {
        val client = clientWithHost("host")
        assertNull(client.connectionInfo)
    }

    @Test
    fun `connectionInfo delegates to active connection`() {
        val connection = mockk<SshConnection>(relaxed = true)
        val info = ConnectionInfo(
            kexAlgorithm = "curve25519-sha256",
            serverHostKeyAlgorithm = "ssh-ed25519",
            encryptionAlgorithmC2S = "aes128-ctr",
            encryptionAlgorithmS2C = "aes128-ctr",
            macAlgorithmC2S = "hmac-sha2-256",
            macAlgorithmS2C = "hmac-sha2-256",
        )
        every { connection.connectionInfo } returns info

        assertEquals(info, connectedClient(connection).connectionInfo)
    }

    @Test
    fun `isAuthenticated is false before connect`() {
        val client = clientWithHost("host")
        assertFalse(client.isAuthenticated)
    }

    @Test
    fun `isAuthenticated requires connection authenticated flag and connected transport`() {
        val connection = mockk<SshConnection>(relaxed = true)

        assertTrue(connectedClient(connection, authenticated = true, transportConnected = true).isAuthenticated)
        assertFalse(connectedClient(connection, authenticated = true, transportConnected = false).isAuthenticated)
        assertFalse(connectedClient(connection, authenticated = false, transportConnected = true).isAuthenticated)
    }

    @Test
    fun `SshClientConfig has default rekey thresholds`() {
        val config = SshClientConfig {
            host = "example.com"
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            }
        }
        assertEquals(3_600_000L, config.rekeyIntervalMs)
        assertEquals(1_073_741_824L, config.rekeyBytesLimit)
    }

    @Test
    fun `SshClientConfig defaults keystroke obfuscation interval to twenty milliseconds`() {
        val config = SshClientConfig {
            host = "example.com"
            hostKeyVerifier = acceptAllVerifier
        }
        assertEquals(20L, config.obscureKeystrokeTimingIntervalMs)
    }

    @Test
    fun `SshClientConfig custom rekey thresholds are applied`() {
        val config = SshClientConfig {
            host = "example.com"
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            }
            rekeyIntervalMs = 60_000L
            rekeyBytesLimit = 1024L
        }
        assertEquals(60_000L, config.rekeyIntervalMs)
        assertEquals(1024L, config.rekeyBytesLimit)
    }

    @Test
    fun `SshClientConfig rejects port 0`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "example.com"
                port = 0
                hostKeyVerifier = acceptAllVerifier
            }
        }
    }

    @Test
    fun `SshClientConfig rejects port 65536`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "example.com"
                port = 65536
                hostKeyVerifier = acceptAllVerifier
            }
        }
    }

    @Test
    fun `SshClientConfig accepts port 1`() {
        SshClientConfig {
            host = "example.com"
            port = 1
            hostKeyVerifier = acceptAllVerifier
        }
    }

    @Test
    fun `SshClientConfig accepts port 65535`() {
        SshClientConfig {
            host = "example.com"
            port = 65535
            hostKeyVerifier = acceptAllVerifier
        }
    }

    @Test
    fun `SshClientConfig rejects blank host`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "  "
                hostKeyVerifier = acceptAllVerifier
            }
        }
    }

    @Test
    fun `SshClientConfig rejects negative keystroke obfuscation interval`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "example.com"
                hostKeyVerifier = acceptAllVerifier
                obscureKeystrokeTimingIntervalMs = -1L
            }
        }
    }

    @Test
    fun `openSftp returns io error when not authenticated`() = runTest {
        val client = clientWithHost("host")

        assertIs<SftpResult.IoError>(client.openSftp())
    }

    @Test
    fun `openSession delegates and handles connection exceptions`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val session = mockk<SessionChannel>()
        val client = connectedClient(connection, authenticated = true)
        coEvery { connection.openSessionChannel() } returns session
        assertEquals(session, client.openSession())

        coEvery { connection.openSessionChannel() } throws IllegalStateException("open failed")
        assertNull(client.openSession())
    }

    @Test
    fun `openSftp maps session open and subsystem failures`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val client = connectedClient(connection, authenticated = true)
        coEvery { connection.openSessionChannel() } returns null
        assertIs<SftpResult.ProtocolError>(client.openSftp())

        val session = mockk<SessionChannel>(relaxed = true)
        coEvery { connection.openSessionChannel() } returns session
        coEvery { session.requestSubsystem("sftp") } returns false
        assertIs<SftpResult.ProtocolError>(client.openSftp())
        verify { session.close() }

        coEvery { connection.openSessionChannel() } throws IllegalStateException("boom")
        assertIs<SftpResult.IoError>(client.openSftp())
    }

    @Test
    fun `localPortForward returns null when not authenticated`() = runTest {
        val client = clientWithHost("host")

        assertNull(client.localPortForward(InetSocketAddress("127.0.0.1", 0), "remote", 22))
        assertNull(client.localPortForward(0, "remote", 22))
    }

    @Test
    fun `localPortForward creates and stops loopback listener when authenticated`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val forwarder = connectedClient(connection, authenticated = true)
            .localPortForward(InetSocketAddress("127.0.0.1", 0), "remote", 22)

        assertTrue(forwarder!!.isActive)
        assertTrue(forwarder.boundPort > 0)
        forwarder.stop()
        assertFalse(forwarder.isActive)
    }

    @Test
    fun `remotePortForward returns null when not authenticated`() = runTest {
        val client = clientWithHost("host")

        assertNull(client.remotePortForward("127.0.0.1", 0, "localhost", 22))
    }

    @Test
    fun `remotePortForward maps server rejection and creates forwarder`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        coEvery { connection.sendTcpipForwardRequest("127.0.0.1", 0) } returns null
        assertNull(connectedClient(connection, authenticated = true).remotePortForward("127.0.0.1", 0, "localhost", 22))

        coEvery { connection.sendTcpipForwardRequest("127.0.0.1", 0) } returns 8022
        val forwarder = connectedClient(connection, authenticated = true)
            .remotePortForward("127.0.0.1", 0, "localhost", 22)

        assertTrue(forwarder!!.isActive)
        assertEquals(8022, forwarder.boundPort)
        forwarder.stop()
        assertFalse(forwarder.isActive)
        verify { connection.registerRemoteForwarder(eq("127.0.0.1:8022"), any()) }
        coVerify { connection.sendCancelTcpipForward("127.0.0.1", 8022) }
    }

    @Test
    fun `dynamicPortForward returns null when not authenticated`() = runTest {
        val client = clientWithHost("host")

        assertNull(client.dynamicPortForward(InetSocketAddress("127.0.0.1", 0)))
        assertNull(client.dynamicPortForward(0))
    }

    @Test
    fun `dynamicPortForward creates and stops loopback listener when authenticated`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val forwarder = connectedClient(connection, authenticated = true)
            .dynamicPortForward(InetSocketAddress("127.0.0.1", 0))

        assertTrue(forwarder!!.isActive)
        assertTrue(forwarder.boundPort > 0)
        forwarder.stop()
        assertFalse(forwarder.isActive)
    }

    @Test
    fun `forwardStream returns null when not authenticated`() = runTest {
        val client = clientWithHost("host")
        val readChannel = ByteChannel(autoFlush = true)
        val writeChannel = ByteChannel(autoFlush = true)

        assertNull(client.forwardStream(readChannel, writeChannel, "remote", 22))
    }

    @Test
    fun `forwardStream maps direct channel failure and success`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val client = connectedClient(connection, authenticated = true)
        coEvery { connection.openDirectTcpipChannel("remote", 22, "127.0.0.1", 0) } returns null

        assertNull(client.forwardStream(ByteChannel(autoFlush = true), ByteChannel(autoFlush = true), "remote", 22))

        val channel = ForwardingChannel(connection, 1, 2, 32768, 32768)
        coEvery { connection.openDirectTcpipChannel("remote", 22, "127.0.0.1", 0) } returns channel
        val forwarder = client.forwardStream(ByteChannel(autoFlush = true), ByteChannel(autoFlush = true), "remote", 22)

        assertTrue(forwarder!!.isActive)
        forwarder.stop()
        assertFalse(forwarder.isActive)
    }

    @Test
    fun `openDirectTcpipTransport returns null when not authenticated`() {
        val client = clientWithHost("host")

        assertNull(client.openDirectTcpipTransport("remote", 22))
    }

    @Test
    fun `openDirectTcpipTransport opens direct tcpip channel from factory`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val channel = ForwardingChannel(connection, 1, 2, 32768, 32768)
        coEvery { connection.openDirectTcpipChannel("remote", 22, "127.0.0.1", 0) } returns channel

        val factory = connectedClient(connection, authenticated = true)
            .openDirectTcpipTransport("remote", 22)

        assertTrue(factory!!.create().isConnected)
    }

    @Test
    fun `openDirectTcpipTransport factory throws when channel open fails`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        coEvery { connection.openDirectTcpipChannel(any(), any(), any(), any()) } returns null

        val factory = connectedClient(connection, authenticated = true)
            .openDirectTcpipTransport("remote", 22)

        assertFailsWith<SshException> {
            factory!!.create()
        }
    }

    @Test
    fun `ping returns not authenticated before connect`() = runTest {
        val client = clientWithHost("host")

        assertEquals(PingResult.NotAuthenticated, client.ping())
    }

    @Test
    fun `ping delegates after authentication`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        coEvery { connection.ping() } returns PingResult.NotSupported

        assertEquals(PingResult.NotSupported, connectedClient(connection, authenticated = true).ping())
    }

    @Test
    fun `disconnect is idempotent before connect`() = runTest {
        val client = clientWithHost("host")

        client.disconnect()

        assertFalse(client.isAuthenticated)
        assertNull(client.connectionInfo)
    }

    @Test
    fun `disconnect closes connection and transport and clears authentication`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        val transport = FakeTransport()
        val client = connectedClient(connection, authenticated = true, transport = transport)

        client.disconnect()

        coVerify { connection.close() }
        assertEquals(1, transport.closeCalls)
        assertFalse(client.isAuthenticated)
        assertNull(client.connectionInfo)
    }

    @Test
    fun `enableAgentForwarding delegates when connected`() {
        val connection = mockk<SshConnection>(relaxed = true)
        val provider = mockk<AgentProvider>()

        connectedClient(connection).enableAgentForwarding(provider)

        verify { connection.enableAgentForwarding(provider) }
    }

    private fun connectedClient(
        connection: SshConnection,
        authenticated: Boolean = false,
        transportConnected: Boolean = true,
        transport: FakeTransport = FakeTransport(transportConnected),
    ): SshClient {
        val config = SshClientConfig {
            host = "host"
            hostKeyVerifier = acceptAllVerifier
        }
        return SshClient.createForTesting(config, transport, connection, authenticated)
    }

    private fun assertAuthError(message: String, result: AuthResult) {
        val error = assertIs<AuthResult.Error>(result)
        assertEquals(message, error.message)
    }

    private class FakeTransport(
        private var connected: Boolean = true,
    ) : Transport {
        var closeCalls = 0

        override val isConnected: Boolean
            get() = connected

        override suspend fun read(count: Int): ByteArray = throw UnsupportedOperationException()

        override suspend fun write(data: ByteArray) = Unit

        override suspend fun close() {
            closeCalls++
            connected = false
        }
    }
}
