/*
 * Copyright 2025 Kenny Root
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

import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.client.AgentProtocolHandler
import org.connectbot.sshlib.client.AgentSessionInfo
import org.connectbot.sshlib.client.SessionBindVerifier
import org.connectbot.sshlib.protocol.SshAgentcSessionBind
import org.connectbot.sshlib.protocol.SshAgentcSignRequest
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

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

    private fun sshString(s: String, charset: java.nio.charset.Charset = Charsets.UTF_8): ByteArray = sshString(s.toByteArray(charset))

    /**
     * Builds the signed data blob for a publickey or publickey-hostbound auth request.
     * Mirrors the format used by SshConnection.buildSignatureData / buildHostBoundSignatureData.
     */
    private fun buildSignedData(
        sessionId: ByteArray = byteArrayOf(0xAA.toByte()),
        username: String = "user",
        methodName: String = "publickey",
        algorithmName: String = "ssh-ed25519",
        publicKeyBlob: ByteArray = byteArrayOf(1, 2, 3),
        serverHostKey: ByteArray? = null,
    ): ByteArray {
        val parts = mutableListOf<ByteArray>()
        parts += sshString(sessionId)
        parts += byteArrayOf(50) // SSH_MSG_USERAUTH_REQUEST
        parts += sshString(username)
        parts += sshString("ssh-connection", Charsets.US_ASCII)
        parts += sshString(methodName, Charsets.US_ASCII)
        parts += byteArrayOf(1) // has_signature = TRUE
        parts += sshString(algorithmName, Charsets.US_ASCII)
        parts += sshString(publicKeyBlob)
        if (serverHostKey != null) parts += sshString(serverHostKey)
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
    private val keyBlob = byteArrayOf(0x01, 0x02, 0x03)

    @Test
    fun `unconstrained key is always allowed`() = runTest {
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = listOf(AgentIdentity(keyBlob, "test"))
            override suspend fun signData(context: AgentSigningContext) = byteArrayOf(0xFF.toByte())
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val signedData = buildSignedData(serverHostKey = hostKeyA)
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(14, msgType) // SSH_AGENT_SIGN_RESPONSE
    }

    @Test
    fun `constrained key direct connection matching destination is allowed`() = runTest {
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
            override suspend fun getIdentities() = listOf(AgentIdentity(keyBlob, "test", constraints))
            override suspend fun signData(context: AgentSigningContext) = byteArrayOf(0xFF.toByte())
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        val signedData = buildSignedData(username = "user", serverHostKey = hostKeyA)
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(14, msgType) // SSH_AGENT_SIGN_RESPONSE
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
            override suspend fun getIdentities() = listOf(AgentIdentity(keyBlob, "test", constraints))
            override suspend fun signData(context: AgentSigningContext) = byteArrayOf(0xFF.toByte())
        }
        // sessionInfo has hostKeyB as the server key — not permitted by the constraint (which requires hostKeyA)
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyB), noopVerifier)

        val signedData = buildSignedData(username = "user")
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
            override suspend fun getIdentities() = listOf(AgentIdentity(keyBlob, "test", constraints))
            override suspend fun signData(context: AgentSigningContext) = byteArrayOf(0xFF.toByte())
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        // Simulate forwarding: bind via hostKeyA, then attempt to sign without hostbound method
        handler.handleRequest(buildSessionBindRequest(hostKeyA, byteArrayOf(1), isForwarding = 0))
        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 1))

        // Standard "publickey" method (not hostbound) should be rejected when forwarding
        val signedData = buildSignedData(methodName = "publickey", username = "user", serverHostKey = hostKeyB)
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(5, msgType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `constrained key forwarding with correct path is allowed`() = runTest {
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
            override suspend fun getIdentities() = listOf(AgentIdentity(keyBlob, "test", constraints))
            override suspend fun signData(context: AgentSigningContext) = byteArrayOf(0xFF.toByte())
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        // Origin bind (non-forwarding) through hostKeyA, then forwarding bind through hostKeyA → hostKeyB
        handler.handleRequest(buildSessionBindRequest(hostKeyA, byteArrayOf(1), isForwarding = 0))
        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 1))

        val signedData = buildSignedData(
            methodName = "publickey-hostbound-v00@openssh.com",
            username = "user",
            serverHostKey = hostKeyB,
        )
        val response = handler.handleRequest(buildSignRequest(keyBlob, signedData))

        val (msgType, _) = parseAgentMessage(response)
        assertEquals(14, msgType) // SSH_AGENT_SIGN_RESPONSE
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
            override suspend fun getIdentities() = listOf(AgentIdentity(keyBlob, "test", constraints))
            override suspend fun signData(context: AgentSigningContext) = byteArrayOf(0xFF.toByte())
        }
        val hostKeyC = byteArrayOf(0x30, 0x31, 0x32)
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyC), noopVerifier)

        // Forwarding through hostKeyC (not in constraints)
        handler.handleRequest(buildSessionBindRequest(hostKeyC, byteArrayOf(1), isForwarding = 0))
        handler.handleRequest(buildSessionBindRequest(hostKeyB, byteArrayOf(2), isForwarding = 1))

        val signedData = buildSignedData(
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
                fromHostname = "hop-a",
                fromKeyspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
                toUsername = "",
                toHostname = "host-b",
                toHostspecs = listOf(AgentKeySpec(hostKeyB, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = listOf(
                AgentIdentity(constrainedKey, "constrained", constraints),
                AgentIdentity(unconstrainedKey, "unconstrained"),
            )
            override suspend fun signData(context: AgentSigningContext) = null
        }
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyA), noopVerifier)

        // Add a forwarding binding through hostKeyA
        handler.handleRequest(buildSessionBindRequest(hostKeyA, byteArrayOf(1), isForwarding = 0))

        val response = handler.handleRequest(buildAgentMessage(11, ByteArray(0)))
        val (msgType, payload) = parseAgentMessage(response)
        assertEquals(12, msgType) // SSH_AGENT_IDENTITIES_ANSWER

        val stream = io.kaitai.struct.ByteBufferKaitaiStream(payload)
        val answer = org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer(stream)
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
                fromHostname = "hop-a",
                fromKeyspecs = listOf(AgentKeySpec(hostKeyA, isCa = false)),
                toUsername = "",
                toHostname = "host-b",
                toHostspecs = listOf(AgentKeySpec(hostKeyB, isCa = false)),
            ),
        )
        val provider = object : AgentProvider {
            override suspend fun getIdentities() = listOf(
                AgentIdentity(constrainedKey, "constrained", constraints),
                AgentIdentity(unconstrainedKey, "unconstrained"),
            )
            override suspend fun signData(context: AgentSigningContext) = null
        }
        // Forwarding through hostKeyC (not hostKeyA, so constrained key not reachable)
        val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(1), hostKeyC), noopVerifier)
        handler.handleRequest(buildSessionBindRequest(hostKeyC, byteArrayOf(1), isForwarding = 0))

        val response = handler.handleRequest(buildAgentMessage(11, ByteArray(0)))
        val (msgType, payload) = parseAgentMessage(response)
        assertEquals(12, msgType) // SSH_AGENT_IDENTITIES_ANSWER

        val stream = io.kaitai.struct.ByteBufferKaitaiStream(payload)
        val answer = org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer(stream)
        answer._read()

        // Only unconstrained key should be visible
        assertEquals(1, answer.nkeys().toInt())
        assert(answer.identities()[0].keyBlob().data().contentEquals(unconstrainedKey))
    }
}
