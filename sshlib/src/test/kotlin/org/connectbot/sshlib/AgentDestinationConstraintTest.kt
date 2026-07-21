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

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.client.AgentProtocolHandler
import org.connectbot.sshlib.client.AgentSessionInfo
import org.connectbot.sshlib.client.SessionBindVerifier
import org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer
import org.connectbot.sshlib.protocol.SshAgentcSessionBind
import org.connectbot.sshlib.protocol.SshAgentcSignRequest
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.charset.Charset

class AgentDestinationConstraintTest {

    private val noopVerifier: SessionBindVerifier = SessionBindVerifier { _, _, _ -> true }

    // Builds a minimal SSH-string encoded byte array (uint32 length + data)
    private fun sshString(data: ByteArray): ByteArray {
        val result = ByteArray(4 + data.size)
        result[0] = (data.size shr 24).toByte()
        result[1] = (data.size shr 16).toByte()
        result[2] = (data.size shr 8).toByte()
        result[3] = data.size.toByte()
        System.arraycopy(data, 0, result, 4, data.size)
        return result
    }

    private fun sshString(s: String, charset: Charset = Charsets.UTF_8): ByteArray = sshString(s.toByteArray(charset))

    /**
     * Builds the signed data blob for a publickey or publickey-hostbound auth request.
     * Mirrors the format used by SshConnection.buildSignatureData / buildHostBoundSignatureData.
     */
    private fun buildSignedData(
        sessionId: ByteArray = byteArrayOf(0xAA.toByte()),
        username: String = "user",
        serviceName: String = "ssh-connection",
        methodName: String = "publickey",
        algorithmName: String = "ssh-ed25519",
        publicKeyBlob: ByteArray = keyBlob,
        serverHostKey: ByteArray? = null,
        trailingData: ByteArray = ByteArray(0),
    ): ByteArray {
        val parts = mutableListOf<ByteArray>()
        parts += sshString(sessionId)
        parts += byteArrayOf(50) // SSH_MSG_USERAUTH_REQUEST
        parts += sshString(username)
        parts += sshString(serviceName, Charsets.US_ASCII)
        parts += sshString(methodName, Charsets.US_ASCII)
        parts += byteArrayOf(1) // has_signature = TRUE
        parts += sshString(algorithmName, Charsets.US_ASCII)
        parts += sshString(publicKeyBlob)
        if (serverHostKey != null) parts += sshString(serverHostKey)
        parts += trailingData
        return parts.fold(ByteArray(0)) { acc, b -> acc + b }
    }

    private fun buildAgentMessage(messageType: Int, payload: ByteArray): ByteArray {
        val totalLength = 1 + payload.size
        val buffer = ByteArray(4 + totalLength)
        buffer[0] = ((totalLength shr 24) and 0xFF).toByte()
        buffer[1] = ((totalLength shr 16) and 0xFF).toByte()
        buffer[2] = ((totalLength shr 8) and 0xFF).toByte()
        buffer[3] = (totalLength and 0xFF).toByte()
        buffer[4] = messageType.toByte()
        System.arraycopy(payload, 0, buffer, 5, payload.size)
        return buffer
    }

    private fun parseAgentMessage(response: ByteArray): Pair<Int, ByteArray> {
        val buffer = ByteBuffer.wrap(response)
        val length = buffer.int
        val messageType = buffer.get().toInt() and 0xFF
        val payload = ByteArray(length - 1)
        buffer.get(payload)
        return Pair(messageType, payload)
    }

    private fun buildSessionBindRequest(
        hostKey: ByteArray,
        sessionId: ByteArray,
        isForwarding: Int,
    ): ByteArray {
        val bind = SshAgentcSessionBind()
        bind.setHostkey(createByteString(hostKey))
        bind.setSessionIdentifier(createByteString(sessionId))
        bind.setSignature(createByteString(byteArrayOf(0x01)))
        bind.setIsForwarding(isForwarding)
        bind._check()

        val nameBytes = createByteString("session-bind@openssh.com".toByteArray()).toByteArray()
        val bindBytes = bind.toByteArray()
        val extBytes = ByteArray(nameBytes.size + bindBytes.size)
        System.arraycopy(nameBytes, 0, extBytes, 0, nameBytes.size)
        System.arraycopy(bindBytes, 0, extBytes, nameBytes.size, bindBytes.size)
        return buildAgentMessage(27, extBytes)
    }

    private fun buildRawSessionBindRequest(
        hostKey: ByteArray,
        sessionId: ByteArray,
        isForwarding: Int,
        trailingData: ByteArray = ByteArray(0),
    ): ByteArray {
        val bindBytes = sshString(hostKey) +
            sshString(sessionId) +
            sshString(byteArrayOf(0x01)) +
            byteArrayOf(isForwarding.toByte()) +
            trailingData
        val extensionPayload = sshString("session-bind@openssh.com") + bindBytes
        return buildAgentMessage(27, extensionPayload)
    }

    private fun buildSignRequest(keyBlob: ByteArray, dataToSign: ByteArray): ByteArray {
        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(createByteString(keyBlob))
        signRequest.setData(createByteString(dataToSign))
        signRequest.setFlags(0)
        signRequest._check()
        return buildAgentMessage(13, signRequest.toByteArray())
    }

    private val hostKeyA = byteArrayOf(0x10, 0x11, 0x12)
    private val hostKeyB = byteArrayOf(0x20, 0x21, 0x22)
    private val keyBlob = sshString("ssh-ed25519", Charsets.US_ASCII) + ByteArray(32) { 0x42 }

    private fun destinationConstraints(
        fromHostKey: ByteArray = hostKeyA,
        toHostKey: ByteArray = hostKeyB,
    ) = listOf(
        DestinationConstraint(
            fromHostname = "",
            fromKeyspecs = emptyList(),
            toUsername = "",
            toHostname = "hop-a",
            toHostspecs = listOf(AgentKeySpec(fromHostKey, isCa = false)),
        ),
        DestinationConstraint(
            fromHostname = "hop-a",
            fromKeyspecs = listOf(AgentKeySpec(fromHostKey, isCa = false)),
            toUsername = "user",
            toHostname = "host-b",
            toHostspecs = listOf(AgentKeySpec(toHostKey, isCa = false)),
        ),
    )

    @Test
    fun `unconstrained key is always allowed`() = runTest {
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test")))
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(byteArrayOf(0xFF.toByte()))
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val signedData = buildSignedData(serverHostKey = hostKeyA)
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(14, msgType) // SSH_AGENT_SIGN_RESPONSE
    }

    @Test
    fun `constrained key cannot sign before destination authenticates its session`() = runTest {
        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "",
                fromKeyspecs = emptyList(),
                toUsername = "user",
                toHostname = "host-a",
                toHostspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(byteArrayOf(0xFF.toByte()))
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val signedData = buildSignedData(
            sessionId = byteArrayOf(1),
            username = "user",
            serverHostKey = hostKeyA,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `constrained key direct connection wrong destination is rejected`() = runTest {
        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "",
                fromKeyspecs = emptyList(),
                toUsername = "user",
                toHostname = "host-a",
                toHostspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(byteArrayOf(0xFF.toByte()))
        }
        // sessionInfo has hostKeyB as the server key — not permitted by the constraint (which requires hostKeyA)
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyB), noopVerifier)

        val signedData = buildSignedData(sessionId = byteArrayOf(1), username = "user")
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `constrained key forwarding without hostbound method is rejected`() = runTest {
        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "hop-a",
                fromKeyspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
                toUsername = "user",
                toHostname = "host-b",
                toHostspecs = listOf(AgentKeySpec(hostKeyB, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(byteArrayOf(0xFF.toByte()))
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        // The handler already has the trusted hostKeyA forwarding binding.
        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0))

        // Standard "publickey" method (not hostbound) should be rejected when forwarding
        val signedData = buildSignedData(
            sessionId = byteArrayOf(2),
            methodName = "publickey",
            username = "user",
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `constrained key forwarding with correct path is allowed`() = runTest {
        val constraints = destinationConstraints()
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(byteArrayOf(0xFF.toByte()))
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val destinationSessionId = byteArrayOf(2)
        handler.handleRequest(buildSessionBindRequest(hostKeyB, destinationSessionId, isForwarding = 0))

        val signedData = buildSignedData(
            sessionId = destinationSessionId,
            methodName = "publickey-hostbound-v00@openssh.com",
            username = "user",
            serverHostKey = hostKeyB,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(14, msgType) // SSH_AGENT_SIGN_RESPONSE
    }

    @Test
    fun `constrained key direct connection with mismatched signed session id is rejected`() = runTest {
        var signCalled = false
        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "",
                fromKeyspecs = emptyList(),
                toUsername = "user",
                toHostname = "host-a",
                toHostspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
                signCalled = true
                return AgentResult.Success(byteArrayOf(0xFF.toByte()))
            }
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val signedData = buildSignedData(
            sessionId = byteArrayOf(9),
            username = "user",
            serverHostKey = hostKeyA,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType)
        assertEquals(false, signCalled)
    }

    @Test
    fun `constrained key forwarded connection with mismatched signed session id is rejected`() = runTest {
        var signCalled = false
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", destinationConstraints())))

            override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
                signCalled = true
                return AgentResult.Success(byteArrayOf(0xFF.toByte()))
            }
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0))

        val signedData = buildSignedData(
            sessionId = byteArrayOf(9),
            methodName = "publickey-hostbound-v00@openssh.com",
            username = "user",
            serverHostKey = hostKeyB,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType)
        assertEquals(false, signCalled)
    }

    @Test
    fun `constrained key forwarded connection with signed host key not matching latest binding is rejected`() = runTest {
        var signCalled = false
        val hostKeyC = byteArrayOf(0x30, 0x31, 0x32)
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", destinationConstraints(toHostKey = hostKeyB))))

            override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
                signCalled = true
                return AgentResult.Success(byteArrayOf(0xFF.toByte()))
            }
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        handler.handleRequest(buildSessionBindRequest(hostKeyC, byteArrayOf(2), isForwarding = 0))

        val signedData = buildSignedData(
            sessionId = byteArrayOf(2),
            methodName = "publickey-hostbound-v00@openssh.com",
            username = "user",
            serverHostKey = hostKeyB,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType)
        assertEquals(false, signCalled)
    }

    @Test
    fun `constrained key cannot sign when latest binding is for forwarding`() = runTest {
        var signCalled = false
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", destinationConstraints())))

            override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
                signCalled = true
                return AgentResult.Success(byteArrayOf(0xFF.toByte()))
            }
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 1))

        val signedData = buildSignedData(
            sessionId = byteArrayOf(2),
            methodName = "publickey-hostbound-v00@openssh.com",
            username = "user",
            serverHostKey = hostKeyB,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType)
        assertEquals(false, signCalled)
    }

    @Test
    fun `authentication binding cannot be extended with another binding`() = runTest {
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(emptyList<AgentIdentity>())
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val hostKeyC = byteArrayOf(0x30, 0x31, 0x32)
        val authResponse = handler.handleRequest(
            buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0),
        )
        val forwardingResponse = handler.handleRequest(
            buildSessionBindRequest(hostKeyC, byteArrayOf(3), isForwarding = 1),
        )

        assertEquals(6, parseAgentMessage(authResponse).first)
        assertEquals(5, parseAgentMessage(forwardingResponse).first)
    }

    @Test
    fun `failed binding attempt prevents constrained signing on same agent connection`() = runTest {
        var signCalled = false
        val constraints = destinationConstraints()
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
                signCalled = true
                return AgentResult.Success(byteArrayOf(0xFF.toByte()))
            }
        }
        val rejectingVerifier = SessionBindVerifier { _, _, _ -> false }
        val handler = AgentProtocolHandler(
            provider,
            AgentSessionInfo(byteArrayOf(1), hostKeyA),
            rejectingVerifier,
        )

        val bindResponse = handler.handleRequest(
            buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0),
        )
        val signedData = buildSignedData(
            sessionId = byteArrayOf(1),
            methodName = "publickey-hostbound-v00@openssh.com",
            serverHostKey = hostKeyA,
        )
        val signResponse = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        assertEquals(5, parseAgentMessage(bindResponse).first)
        assertEquals(5, parseAgentMessage(signResponse).first)
        assertEquals(false, signCalled)
    }

    @Test
    fun `constrained key forwarding through wrong hop is rejected`() = runTest {
        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "hop-a",
                fromKeyspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
                toUsername = "user",
                toHostname = "host-b",
                toHostspecs = listOf(AgentKeySpec(hostKeyB, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(listOf(AgentIdentity(keyBlob, "test", constraints)))
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(byteArrayOf(0xFF.toByte()))
        }
        val hostKeyC = byteArrayOf(0x30, 0x31, 0x32)
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyC), noopVerifier)

        // Forwarding through hostKeyC (not in constraints)
        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0))

        val signedData = buildSignedData(
            sessionId = byteArrayOf(2),
            methodName = "publickey-hostbound-v00@openssh.com",
            username = "user",
            serverHostKey = hostKeyB,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `REQUEST_IDENTITIES on forwarded connection only returns reachable keys`() = runTest {
        val constrainedKey = byteArrayOf(0xAA.toByte(), 0xBB.toByte())
        val unconstrainedKey = byteArrayOf(0xCC.toByte(), 0xDD.toByte())

        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "",
                fromKeyspecs = emptyList(),
                toUsername = "",
                toHostname = "hop-a",
                toHostspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
            ),
            DestinationConstraint(
                fromHostname = "hop-a",
                fromKeyspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
                toUsername = "",
                toHostname = "host-b",
                toHostspecs = listOf(AgentKeySpec(hostKeyB, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(
                listOf(
                    AgentIdentity(constrainedKey, "constrained", constraints),
                    AgentIdentity(unconstrainedKey, "unconstrained"),
                ),
            )
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val response = handler.handleRequest(buildAgentMessage(11, ByteArray(0)))
        val (msgType, payload) = parseAgentMessage(response)
        assertEquals(12, msgType) // SSH_AGENT_IDENTITIES_ANSWER

        val stream = ByteBufferKaitaiStream(payload)
        val answer = SshAgentIdentitiesAnswer(stream)
        answer._read()

        // Only unconstrained key should be visible (constrained key needs fromKeyspecs=hostKeyA
        // but it's found in the last hop — wait, hostKeyA IS the last hop here, so constrained
        // key IS reachable). Both should appear.
        assertEquals(2, answer.nkeys().toInt())
    }

    @Test
    fun `constrained key not reachable via current hop is hidden`() = runTest {
        val constrainedKey = byteArrayOf(0xAA.toByte(), 0xBB.toByte())
        val unconstrainedKey = byteArrayOf(0xCC.toByte(), 0xDD.toByte())

        val hostKeyC = byteArrayOf(0x30, 0x31, 0x32)
        val constraints = listOf(
            DestinationConstraint(
                fromHostname = "",
                fromKeyspecs = emptyList(),
                toUsername = "",
                toHostname = "hop-a",
                toHostspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
            ),
            DestinationConstraint(
                fromHostname = "hop-a",
                fromKeyspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
                toUsername = "",
                toHostname = "host-b",
                toHostspecs = listOf(AgentKeySpec(hostKeyB, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(
                listOf(
                    AgentIdentity(constrainedKey, "constrained", constraints),
                    AgentIdentity(unconstrainedKey, "unconstrained"),
                ),
            )
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
        }
        // Forwarding through hostKeyC (not hostKeyA, so constrained key not reachable)
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyC), noopVerifier)

        val response = handler.handleRequest(buildAgentMessage(11, ByteArray(0)))
        val (msgType, payload) = parseAgentMessage(response)
        assertEquals(12, msgType) // SSH_AGENT_IDENTITIES_ANSWER

        val stream = ByteBufferKaitaiStream(payload)
        val answer = SshAgentIdentitiesAnswer(stream)
        answer._read()

        // Only unconstrained key should be visible
        assertEquals(1, answer.nkeys().toInt())
        assert(answer.identities()[0].keyBlob().data().contentEquals(unconstrainedKey))
    }

    @Test
    fun `constrained signing rejects malformed or inconsistent userauth data`() = runTest {
        var signCalls = 0
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(
                listOf(
                    AgentIdentity(keyBlob, "test", destinationConstraints()),
                ),
            )

            override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
                signCalls++
                return AgentResult.Success(byteArrayOf(0x7F))
            }
        }
        val invalidSignedData = listOf(
            buildSignedData(
                sessionId = byteArrayOf(2),
                serviceName = "not-ssh-connection",
                methodName = "publickey-hostbound-v00@openssh.com",
                serverHostKey = hostKeyB,
            ),
            buildSignedData(
                sessionId = byteArrayOf(2),
                methodName = "keyboard-interactive",
                serverHostKey = hostKeyB,
            ),
            buildSignedData(
                sessionId = byteArrayOf(2),
                methodName = "publickey-hostbound-v00@openssh.com",
                publicKeyBlob = keyBlob + byteArrayOf(0),
                serverHostKey = hostKeyB,
            ),
            buildSignedData(
                sessionId = byteArrayOf(2),
                methodName = "publickey-hostbound-v00@openssh.com",
                algorithmName = "ssh-rsa",
                serverHostKey = hostKeyB,
            ),
            buildSignedData(
                sessionId = byteArrayOf(2),
                methodName = "publickey-hostbound-v00@openssh.com",
                serverHostKey = hostKeyB,
                trailingData = byteArrayOf(0),
            ),
        )

        for (signedData in invalidSignedData) {
            val handler = AgentProtocolHandler(
                provider,
                AgentSessionInfo(byteArrayOf(1), hostKeyA),
                noopVerifier,
            )
            assertEquals(
                6,
                parseAgentMessage(
                    handler.handleRequest(
                        buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0),
                    ),
                ).first,
            )

            val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))
            assertEquals(5, parseAgentMessage(response).first)
        }
        assertEquals(0, signCalls)
    }

    @Test
    fun `session binding enforces length count and trailing data limits`() = runTest {
        var verifyCalls = 0
        val verifier = SessionBindVerifier { _, _, _ ->
            verifyCalls++
            true
        }
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(emptyList<AgentIdentity>())
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
        }
        val handler = AgentProtocolHandler(
            provider,
            AgentSessionInfo(byteArrayOf(1), hostKeyA),
            verifier,
        )

        val oversized = handler.handleRequest(
            buildRawSessionBindRequest(hostKeyB, ByteArray(129), isForwarding = 1),
        )
        val trailing = handler.handleRequest(
            buildRawSessionBindRequest(hostKeyB, byteArrayOf(99), isForwarding = 1, trailingData = byteArrayOf(0)),
        )
        assertEquals(5, parseAgentMessage(oversized).first)
        assertEquals(5, parseAgentMessage(trailing).first)
        assertEquals(0, verifyCalls)

        for (value in 2..16) {
            val response = handler.handleRequest(
                buildRawSessionBindRequest(hostKeyB, byteArrayOf(value.toByte()), isForwarding = 1),
            )
            assertEquals(6, parseAgentMessage(response).first)
        }
        assertEquals(15, verifyCalls)

        val overLimit = handler.handleRequest(
            buildRawSessionBindRequest(hostKeyB, byteArrayOf(17), isForwarding = 1),
        )
        assertEquals(5, parseAgentMessage(overLimit).first)
        assertEquals(15, verifyCalls)
    }

    @Test
    fun `session bind verifier exceptions fail closed`() = runTest {
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(emptyList<AgentIdentity>())
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success(null)
        }
        val handler = AgentProtocolHandler(
            provider,
            AgentSessionInfo(byteArrayOf(1), hostKeyA),
            SessionBindVerifier { _, _, _ -> error("verifier failure") },
        )

        val response = handler.handleRequest(
            buildRawSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 0),
        )
        assertEquals(5, parseAgentMessage(response).first)
    }
}
