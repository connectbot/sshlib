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
import org.connectbot.sshlib.client.AgentProtocolHandler
import org.connectbot.sshlib.client.AgentSessionInfo
import org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer
import org.connectbot.sshlib.protocol.SshAgentMessage
import org.connectbot.sshlib.protocol.SshAgentSignResponse
import org.connectbot.sshlib.protocol.SshAgentcRequestIdentities
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
                AgentIdentity(byteArrayOf(4, 5, 6), "key2")
            )

            override suspend fun signData(context: AgentSigningContext): ByteArray? = null
        }

        val sessionInfo = AgentSessionInfo(
            sessionId = byteArrayOf(1, 2, 3),
            serverHostKey = byteArrayOf(4, 5, 6)
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
            serverHostKey = byteArrayOf(4, 5, 6)
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
            serverHostKey = byteArrayOf(4, 5, 6)
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
            serverHostKey = byteArrayOf(13, 14, 15)
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
}
