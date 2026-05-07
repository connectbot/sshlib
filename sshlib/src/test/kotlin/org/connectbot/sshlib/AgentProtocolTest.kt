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

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.test.runTest
import nl.jqno.equalsverifier.EqualsVerifier
import org.connectbot.sshlib.client.AgentProtocolHandler
import org.connectbot.sshlib.client.AgentSessionInfo
import org.connectbot.sshlib.client.BindingEntry
import org.connectbot.sshlib.client.SessionBindVerifier
import org.connectbot.sshlib.client.SignedDataComponents
import org.connectbot.sshlib.client.buildAgentMessage
import org.connectbot.sshlib.client.isConstraintSatisfied
import org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer
import org.connectbot.sshlib.protocol.SshAgentMessage
import org.connectbot.sshlib.protocol.SshAgentSignResponse
import org.connectbot.sshlib.protocol.SshAgentcExtension
import org.connectbot.sshlib.protocol.SshAgentcRequestIdentities
import org.connectbot.sshlib.protocol.SshAgentcSessionBind
import org.connectbot.sshlib.protocol.SshAgentcSignRequest
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class AgentProtocolTest {

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

    @Test
    fun `parse REQUEST_IDENTITIES message`() {
        val requestMessage = buildAgentMessage(11, ByteArray(0))

        val stream = ByteBufferKaitaiStream(requestMessage)
        val message = SshAgentMessage(stream)
        message._read()

        assertEquals(11, message.messageType())
        assertTrue(message.payload() is SshAgentcRequestIdentities)
    }

    @Test
    fun `parse SIGN_REQUEST message`() {
        val keyBlob = createByteString(byteArrayOf(1, 2, 3, 4))
        val dataToSign = createByteString(byteArrayOf(5, 6, 7, 8))

        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(keyBlob)
        signRequest.setData(dataToSign)
        signRequest.setFlags(0)
        signRequest._check()

        val requestBytes = signRequest.toByteArray()
        val requestMessage = buildAgentMessage(13, requestBytes)

        val stream = ByteBufferKaitaiStream(requestMessage)
        val message = SshAgentMessage(stream)
        message._read()

        assertEquals(13, message.messageType())
        val payload = message.payload() as SshAgentcSignRequest
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), payload.keyBlob().data())
        assertArrayEquals(byteArrayOf(5, 6, 7, 8), payload.data().data())
        assertEquals(0, payload.flags().toInt())
    }

    @Test
    fun `handler returns identities answer`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = listOf(
                AgentIdentity(byteArrayOf(1, 2, 3), "key1"),
                AgentIdentity(byteArrayOf(4, 5, 6), "key2"),
            )

            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionInfo = AgentSessionInfo(
            sessionId = byteArrayOf(1, 2, 3),
            serverHostKey = byteArrayOf(4, 5, 6),
        )

        val handler = AgentProtocolHandler(testProvider, sessionInfo)

        val requestMessage = buildAgentMessage(11, ByteArray(0))
        val response = handler.handleRequest(requestMessage)

        val (messageType, payload) = parseAgentMessage(response)
        assertEquals(12, messageType) // SSH_AGENT_IDENTITIES_ANSWER

        val stream = ByteBufferKaitaiStream(payload)
        val answer = SshAgentIdentitiesAnswer(stream)
        answer._read()

        assertEquals(2, answer.nkeys().toInt())
        assertEquals(2, answer.identities().size)
        assertArrayEquals(byteArrayOf(1, 2, 3), answer.identities()[0].keyBlob().data())
        assertArrayEquals("key1".toByteArray(), answer.identities()[0].comment().data())
    }

    @Test
    fun `handler returns sign response when provider approves`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()

            override suspend fun signData(context: AgentSigningContext): ByteArray? = byteArrayOf(9, 8, 7, 6, 5)
        }

        val sessionInfo = AgentSessionInfo(
            sessionId = byteArrayOf(1, 2, 3),
            serverHostKey = byteArrayOf(4, 5, 6),
        )

        val handler = AgentProtocolHandler(testProvider, sessionInfo)

        val keyBlob = createByteString(byteArrayOf(1, 2, 3, 4))
        val dataToSign = createByteString(byteArrayOf(5, 6, 7, 8))
        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(keyBlob)
        signRequest.setData(dataToSign)
        signRequest.setFlags(0)
        signRequest._check()

        val requestMessage = buildAgentMessage(13, signRequest.toByteArray())
        val response = handler.handleRequest(requestMessage)

        val (messageType, payload) = parseAgentMessage(response)
        assertEquals(14, messageType) // SSH_AGENT_SIGN_RESPONSE

        val stream = ByteBufferKaitaiStream(payload)
        val signResponse = SshAgentSignResponse(stream)
        signResponse._read()

        assertArrayEquals(byteArrayOf(9, 8, 7, 6, 5), signResponse.signature().data())
    }

    @Test
    fun `handler returns failure when provider denies`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()

            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionInfo = AgentSessionInfo(
            sessionId = byteArrayOf(1, 2, 3),
            serverHostKey = byteArrayOf(4, 5, 6),
        )

        val handler = AgentProtocolHandler(testProvider, sessionInfo)

        val keyBlob = createByteString(byteArrayOf(1, 2, 3, 4))
        val dataToSign = createByteString(byteArrayOf(5, 6, 7, 8))
        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(keyBlob)
        signRequest.setData(dataToSign)
        signRequest.setFlags(0)
        signRequest._check()

        val requestMessage = buildAgentMessage(13, signRequest.toByteArray())
        val response = handler.handleRequest(requestMessage)

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(5, messageType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `provider receives correct context`() = runTest {
        var capturedContext: AgentSigningContext? = null

        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()

            override suspend fun signData(context: AgentSigningContext): ByteArray? {
                capturedContext = context
                return byteArrayOf(1, 2, 3)
            }
        }

        val sessionInfo = AgentSessionInfo(
            sessionId = byteArrayOf(10, 11, 12),
            serverHostKey = byteArrayOf(13, 14, 15),
        )

        val handler = AgentProtocolHandler(testProvider, sessionInfo)

        val keyBlob = createByteString(byteArrayOf(1, 2, 3, 4))
        val dataToSign = createByteString(byteArrayOf(5, 6, 7, 8))
        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(keyBlob)
        signRequest.setData(dataToSign)
        signRequest.setFlags(2)
        signRequest._check()

        val requestMessage = buildAgentMessage(13, signRequest.toByteArray())
        handler.handleRequest(requestMessage)

        assertNotNull(capturedContext)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), capturedContext!!.publicKeyBlob)
        assertArrayEquals(byteArrayOf(5, 6, 7, 8), capturedContext.dataToSign)
        assertEquals(2, capturedContext.flags)
        assertArrayEquals(byteArrayOf(10, 11, 12), capturedContext.sessionId)
        assertArrayEquals(byteArrayOf(13, 14, 15), capturedContext.serverHostKey)
        assertFalse(capturedContext.isBound)
    }

    private fun buildSessionBindRequest(
        hostKey: ByteArray,
        sessionId: ByteArray,
        isForwarding: Int,
    ): ByteArray {
        val bind = SshAgentcSessionBind()
        bind.setHostkey(createByteString(hostKey))
        bind.setSessionIdentifier(createByteString(sessionId))
        bind.setSignature(createByteString(byteArrayOf(1, 2, 3)))
        bind.setIsForwarding(isForwarding)
        bind._check()

        val nameBytes = createByteString("session-bind@openssh.com".toByteArray()).toByteArray()
        val bindBytes = bind.toByteArray()
        val extBytes = ByteArray(nameBytes.size + bindBytes.size)
        System.arraycopy(nameBytes, 0, extBytes, 0, nameBytes.size)
        System.arraycopy(bindBytes, 0, extBytes, nameBytes.size, bindBytes.size)
        return buildAgentMessage(27, extBytes)
    }

    private val noopVerifier: SessionBindVerifier = SessionBindVerifier { _, _, _ -> true }
    private val rejectingVerifier: SessionBindVerifier = SessionBindVerifier { _, _, _ -> false }

    @Test
    fun `handler handles session bind extension`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionId = byteArrayOf(1, 2, 3)
        val hostKey = byteArrayOf(4, 5, 6)
        val sessionInfo = AgentSessionInfo(sessionId, hostKey)
        val handler = AgentProtocolHandler(testProvider, sessionInfo, noopVerifier)

        val response = handler.handleRequest(buildSessionBindRequest(hostKey, sessionId, isForwarding = 1))

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(6, messageType) // SSH_AGENT_SUCCESS
    }

    @Test
    fun `handler rejects session bind when signature verification fails`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionId = byteArrayOf(1, 2, 3)
        val hostKey = byteArrayOf(4, 5, 6)
        val sessionInfo = AgentSessionInfo(sessionId, hostKey)
        val handler = AgentProtocolHandler(testProvider, sessionInfo, rejectingVerifier)

        val response = handler.handleRequest(buildSessionBindRequest(hostKey, sessionId, isForwarding = 1))

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(5, messageType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `handler rejects duplicate session bind`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionId = byteArrayOf(1, 2, 3)
        val hostKey = byteArrayOf(4, 5, 6)
        val sessionInfo = AgentSessionInfo(sessionId, hostKey)
        val handler = AgentProtocolHandler(testProvider, sessionInfo, noopVerifier)

        val requestMessage = buildSessionBindRequest(hostKey, sessionId, isForwarding = 1)
        handler.handleRequest(requestMessage)
        val response = handler.handleRequest(requestMessage)

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(5, messageType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `handler rejects non-forwarding session bind with mismatched hostkey`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionInfo = AgentSessionInfo(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
        val handler = AgentProtocolHandler(testProvider, sessionInfo, noopVerifier)

        // is_forwarding = 0 means origin bind — hostkey must match sessionInfo.serverHostKey
        val response = handler.handleRequest(
            buildSessionBindRequest(byteArrayOf(9, 9, 9), byteArrayOf(1, 2, 3), isForwarding = 0),
        )

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(5, messageType) // SSH_AGENT_FAILURE
    }

    @Test
    fun `handler accumulates multiple forwarding binds`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val hostKey = byteArrayOf(4, 5, 6)
        val sessionInfo = AgentSessionInfo(byteArrayOf(1, 2, 3), hostKey)
        val handler = AgentProtocolHandler(testProvider, sessionInfo, noopVerifier)

        val response1 = handler.handleRequest(buildSessionBindRequest(hostKey, byteArrayOf(1, 2, 3), isForwarding = 0))
        val (type1, _) = parseAgentMessage(response1)
        assertEquals(6, type1)

        val response2 = handler.handleRequest(buildSessionBindRequest(byteArrayOf(7, 8, 9), byteArrayOf(4, 5, 6), isForwarding = 1))
        val (type2, _) = parseAgentMessage(response2)
        assertEquals(6, type2)
    }

    @Test
    fun `handler returns failure for unknown extension`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }
        val handler = AgentProtocolHandler(testProvider, AgentSessionInfo(byteArrayOf(), byteArrayOf()))

        val nameBytes = createByteString("unknown@example.com".toByteArray()).toByteArray()
        val dataBytes = byteArrayOf(1, 2, 3)
        val extBytes = ByteArray(nameBytes.size + dataBytes.size)
        System.arraycopy(nameBytes, 0, extBytes, 0, nameBytes.size)
        System.arraycopy(dataBytes, 0, extBytes, nameBytes.size, dataBytes.size)

        val requestMessage = buildAgentMessage(27, extBytes)
        val response = handler.handleRequest(requestMessage)

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(5, messageType)
    }

    @Test
    fun `handler returns failure for unknown message type`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }
        val handler = AgentProtocolHandler(testProvider, AgentSessionInfo(byteArrayOf(), byteArrayOf()))

        val requestMessage = buildAgentMessage(99, byteArrayOf(1, 2, 3))
        val response = handler.handleRequest(requestMessage)

        val (messageType, _) = parseAgentMessage(response)
        assertEquals(5, messageType)
    }

    @Test
    fun `AgentSessionInfo equals and hashCode`() {
        EqualsVerifier.forClass(AgentSessionInfo::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }

    @Test
    fun `buildAgentMessage encodes length field correctly for 255-byte signature`() = runTest {
        // A 255-byte signature makes the SIGN_RESPONSE payload large enough that byte[2] of the
        // length field is non-zero. Routes through the production buildAgentMessage (not the local helper).
        val largeSignature = ByteArray(255) { it.toByte() }
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray = largeSignature
        }
        val handler = AgentProtocolHandler(testProvider, AgentSessionInfo(byteArrayOf(1), byteArrayOf(2)))
        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(createByteString(byteArrayOf(1)))
        signRequest.setData(createByteString(byteArrayOf(2)))
        signRequest.setFlags(0)
        signRequest._check()
        val response = handler.handleRequest(buildAgentMessage(13, signRequest.toByteArray()))
        val (messageType, payload) = parseAgentMessage(response)
        assertEquals(14, messageType)
        val sig = SshAgentSignResponse(ByteBufferKaitaiStream(payload))
        sig._read()
        assertArrayEquals(largeSignature, sig.signature().data())
    }

    @Test
    fun `buildAgentMessage encodes length field correctly for 65535-byte signature`() = runTest {
        // A 65535-byte signature forces byte[1] of the length field to be non-zero.
        // Routes through the production buildAgentMessage.
        val hugeSignature = ByteArray(65535) { it.toByte() }
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = emptyList()
            override suspend fun signData(context: AgentSigningContext): ByteArray = hugeSignature
        }
        val handler = AgentProtocolHandler(testProvider, AgentSessionInfo(byteArrayOf(1), byteArrayOf(2)))
        val signRequest = SshAgentcSignRequest()
        signRequest.setKeyBlob(createByteString(byteArrayOf(1)))
        signRequest.setData(createByteString(byteArrayOf(2)))
        signRequest.setFlags(0)
        signRequest._check()
        val response = handler.handleRequest(buildAgentMessage(13, signRequest.toByteArray()))
        val (messageType, payload) = parseAgentMessage(response)
        assertEquals(14, messageType)
        val sig = SshAgentSignResponse(ByteBufferKaitaiStream(payload))
        sig._read()
        assertArrayEquals(hugeSignature, sig.signature().data())
    }
}

class BuildAgentMessageTest {

    private fun parseMessage(bytes: ByteArray): Pair<Int, ByteArray> {
        val buf = ByteBuffer.wrap(bytes)
        val length = buf.int
        val msgType = buf.get().toInt() and 0xFF
        val payload = ByteArray(length - 1)
        buf.get(payload)
        return msgType to payload
    }

    @Test
    fun `empty payload encodes correctly`() {
        val result = buildAgentMessage(5, ByteArray(0))
        val (msgType, payload) = parseMessage(result)
        assertEquals(5, msgType)
        assertArrayEquals(ByteArray(0), payload)
    }

    @Test
    fun `small payload roundtrips`() {
        val data = byteArrayOf(1, 2, 3)
        val result = buildAgentMessage(14, data)
        val (msgType, payload) = parseMessage(result)
        assertEquals(14, msgType)
        assertArrayEquals(data, payload)
    }

    @Test
    fun `255-byte payload makes byte 2 of length non-zero`() {
        val data = ByteArray(255) { it.toByte() }
        val result = buildAgentMessage(12, data)
        val (msgType, payload) = parseMessage(result)
        assertEquals(12, msgType)
        assertArrayEquals(data, payload)
        assertTrue(result[2] != 0.toByte()) { "byte[2] should be non-zero for payload size 255" }
    }

    @Test
    fun `65535-byte payload makes byte 1 of length non-zero`() {
        val data = ByteArray(65535) { it.toByte() }
        val result = buildAgentMessage(6, data)
        val (msgType, payload) = parseMessage(result)
        assertEquals(6, msgType)
        assertArrayEquals(data, payload)
        assertTrue(result[1] != 0.toByte()) { "byte[1] should be non-zero for payload size 65535" }
    }
}

class IsConstraintSatisfiedTest {

    private fun constraint(
        fromHostname: String = "",
        fromKeyspecs: List<AgentKeySpec> = emptyList(),
        toUsername: String = "",
        toHostname: String = "",
        toHostspecs: List<AgentKeySpec> = emptyList(),
    ) = DestinationConstraint(fromHostname, fromKeyspecs, toUsername, toHostname, toHostspecs)

    private fun keyspec(blob: ByteArray) = AgentKeySpec(blob, false)

    private val hostKey = byteArrayOf(0x01, 0x02, 0x03)
    private val sessionId = byteArrayOf(0x04, 0x05, 0x06)

    @Test
    fun `direct connection - no constraints - always rejected`() {
        val components = SignedDataComponents("publickey", "user", hostKey)
        assertFalse(isConstraintSatisfied(emptyList(), components, emptyList()))
    }

    @Test
    fun `direct connection - empty from constraint with matching toHostspec - satisfied`() {
        val c = constraint(toHostspecs = listOf(keyspec(hostKey)))
        val components = SignedDataComponents("publickey", "user", hostKey)
        assertTrue(isConstraintSatisfied(listOf(c), components, emptyList()))
    }

    @Test
    fun `direct connection - empty from constraint with non-matching toHostspec - rejected`() {
        val c = constraint(toHostspecs = listOf(keyspec(byteArrayOf(0x99.toByte()))))
        val components = SignedDataComponents("publickey", "user", hostKey)
        assertFalse(isConstraintSatisfied(listOf(c), components, emptyList()))
    }

    @Test
    fun `direct connection - toUsername mismatch - rejected`() {
        val c = constraint(toHostspecs = listOf(keyspec(hostKey)), toUsername = "alice")
        val components = SignedDataComponents("publickey", "bob", hostKey)
        assertFalse(isConstraintSatisfied(listOf(c), components, emptyList()))
    }

    @Test
    fun `direct connection - toUsername matches - satisfied`() {
        val c = constraint(toHostspecs = listOf(keyspec(hostKey)), toUsername = "alice")
        val components = SignedDataComponents("publickey", "alice", hostKey)
        assertTrue(isConstraintSatisfied(listOf(c), components, emptyList()))
    }

    @Test
    fun `direct connection - null serverHostKeyBlob - rejected`() {
        val c = constraint(toHostspecs = listOf(keyspec(hostKey)))
        val components = SignedDataComponents("publickey", "user", null)
        assertFalse(isConstraintSatisfied(listOf(c), components, emptyList()))
    }

    @Test
    fun `forwarded connection - single binding - fromKeyspec matches hop - satisfied`() {
        val hopKey = byteArrayOf(0xAA.toByte())
        val destKey = byteArrayOf(0xBB.toByte())
        val binding = BindingEntry(hopKey, sessionId)
        val c = constraint(fromKeyspecs = listOf(keyspec(hopKey)), toHostspecs = listOf(keyspec(destKey)))
        val components = SignedDataComponents("publickey-hostbound-v00@openssh.com", "user", destKey)
        assertTrue(isConstraintSatisfied(listOf(c), components, listOf(binding)))
    }

    @Test
    fun `forwarded connection - single binding - fromKeyspec does not match - rejected`() {
        val hopKey = byteArrayOf(0xAA.toByte())
        val wrongKey = byteArrayOf(0xCC.toByte())
        val destKey = byteArrayOf(0xBB.toByte())
        val binding = BindingEntry(hopKey, sessionId)
        val c = constraint(fromKeyspecs = listOf(keyspec(wrongKey)), toHostspecs = listOf(keyspec(destKey)))
        val components = SignedDataComponents("publickey-hostbound-v00@openssh.com", "user", destKey)
        assertFalse(isConstraintSatisfied(listOf(c), components, listOf(binding)))
    }

    @Test
    fun `forwarded connection - two bindings - uses second-to-last as hop key`() {
        val hop1Key = byteArrayOf(0xAA.toByte())
        val hop2Key = byteArrayOf(0xBB.toByte())
        val destKey = byteArrayOf(0xCC.toByte())
        val bindings = listOf(BindingEntry(hop1Key, byteArrayOf(1)), BindingEntry(hop2Key, byteArrayOf(2)))
        val c = constraint(fromKeyspecs = listOf(keyspec(hop1Key)), toHostspecs = listOf(keyspec(destKey)))
        val components = SignedDataComponents("publickey-hostbound-v00@openssh.com", "user", destKey)
        assertTrue(isConstraintSatisfied(listOf(c), components, bindings))
    }
}

class BindingEntryEqualsTest {

    @Test
    fun `equals and hashCode`() {
        EqualsVerifier.forClass(BindingEntry::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }
}

class SignedDataComponentsEqualsTest {

    @Test
    fun `equals and hashCode`() {
        EqualsVerifier.forClass(SignedDataComponents::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }
}
