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

package org.connectbot.sshlib.client

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStruct
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AgentSigningContext
import org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer
import org.connectbot.sshlib.protocol.SshAgentMessage
import org.connectbot.sshlib.protocol.SshAgentSignResponse
import org.connectbot.sshlib.protocol.SshAgentcExtension
import org.connectbot.sshlib.protocol.SshAgentcSessionBind
import org.connectbot.sshlib.protocol.SshAgentcSignRequest
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.slf4j.LoggerFactory

internal class AgentProtocolHandler(
    private val provider: AgentProvider,
    private val sessionInfo: AgentSessionInfo,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(AgentProtocolHandler::class.java)

        const val SSH_AGENTC_REQUEST_IDENTITIES: Int = 11
        const val SSH_AGENT_IDENTITIES_ANSWER: Int = 12
        const val SSH_AGENTC_SIGN_REQUEST: Int = 13
        const val SSH_AGENT_SIGN_RESPONSE: Int = 14
        const val SSH_AGENT_FAILURE: Int = 5
        const val SSH_AGENTC_EXTENSION: Int = 27
        const val SSH_AGENT_SUCCESS: Int = 6
    }

    private var sessionBound = false
    private var boundSessionId: ByteArray? = null

    suspend fun handleRequest(requestBytes: ByteArray): ByteArray {
        logger.debug("Handling agent request (${requestBytes.size} bytes)")

        val stream = ByteBufferKaitaiStream(requestBytes)
        val message = SshAgentMessage(stream)
        message._read()

        val messageType = message.messageType()
        logger.debug("Agent message type: $messageType")

        return when (messageType) {
            SSH_AGENTC_REQUEST_IDENTITIES -> handleRequestIdentities()

            SSH_AGENTC_SIGN_REQUEST -> handleSignRequest(message)

            SSH_AGENTC_EXTENSION -> handleExtension(message)

            else -> {
                logger.warn("Unknown agent message type: $messageType")
                createFailureResponse()
            }
        }
    }

    private suspend fun handleRequestIdentities(): ByteArray {
        logger.debug("Handling REQUEST_IDENTITIES")

        val identities = provider.getIdentities()
        logger.debug("Provider returned ${identities.size} identities")

        val response = SshAgentIdentitiesAnswer()
        response.setNkeys(identities.size.toLong())

        val identityList = ArrayList<SshAgentIdentitiesAnswer.Identity>()
        for (identity in identities) {
            val id = SshAgentIdentitiesAnswer.Identity()
            id.set_root(response)
            id.set_parent(response)
            id.setKeyBlob(createByteString(identity.publicKeyBlob))
            id.setComment(createByteString(identity.comment.toByteArray(Charsets.UTF_8)))
            id._check()
            identityList.add(id)
        }
        response.setIdentities(identityList)
        response._check()

        return buildAgentMessage(SSH_AGENT_IDENTITIES_ANSWER, response.toByteArray())
    }

    private suspend fun handleSignRequest(message: SshAgentMessage): ByteArray {
        logger.debug("Handling SIGN_REQUEST")

        val payload = parsePayload<SshAgentcSignRequest>(message)

        val context = AgentSigningContext(
            publicKeyBlob = payload.keyBlob().data(),
            dataToSign = payload.data().data(),
            flags = payload.flags().toInt(),
            sessionId = boundSessionId ?: sessionInfo.sessionId,
            serverHostKey = sessionInfo.serverHostKey,
            isBound = sessionBound,
        )

        logger.debug("Requesting signature from provider (bound=$sessionBound, flags=${context.flags})")

        val signature = provider.signData(context)

        return if (signature != null) {
            logger.debug("Provider approved signing request")
            val response = SshAgentSignResponse()
            response.setSignature(createByteString(signature))
            response._check()
            buildAgentMessage(SSH_AGENT_SIGN_RESPONSE, response.toByteArray())
        } else {
            logger.info("Provider denied signing request")
            createFailureResponse()
        }
    }

    private suspend fun handleExtension(message: SshAgentMessage): ByteArray {
        logger.debug("Handling EXTENSION")

        val ext = parsePayload<SshAgentcExtension>(message)
        val extensionName = String(ext.extensionName().data(), Charsets.UTF_8)

        logger.debug("Extension name: $extensionName")

        return if (extensionName == "session-bind@openssh.com") {
            handleSessionBind(ext.extensionData())
        } else {
            logger.warn("Unknown extension: $extensionName")
            createFailureResponse()
        }
    }

    private fun handleSessionBind(extensionData: ByteArray): ByteArray {
        logger.debug("Handling session-bind@openssh.com extension")

        val stream = ByteBufferKaitaiStream(extensionData)
        val bind = SshAgentcSessionBind(stream)
        bind._read()

        if (sessionBound) {
            logger.warn("Session already bound, rejecting duplicate binding")
            return createFailureResponse()
        }

        if (!bind.hostkey().data().contentEquals(sessionInfo.serverHostKey)) {
            logger.error("Session bind hostkey mismatch")
            return createFailureResponse()
        }

        sessionBound = true
        boundSessionId = bind.sessionIdentifier().data()

        logger.info("Session binding successful")
        return createSuccessResponse()
    }

    private inline fun <reified T : KaitaiStruct.ReadWrite> parsePayload(message: SshAgentMessage): T {
        val stream = ByteBufferKaitaiStream(message._raw_payload())
        val payload = T::class.java.getConstructor(io.kaitai.struct.KaitaiStream::class.java).newInstance(stream)
        payload._read()
        return payload
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

    private fun createFailureResponse(): ByteArray = buildAgentMessage(SSH_AGENT_FAILURE, ByteArray(0))

    private fun createSuccessResponse(): ByteArray = buildAgentMessage(SSH_AGENT_SUCCESS, ByteArray(0))
}

internal data class AgentSessionInfo(
    val sessionId: ByteArray,
    val serverHostKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AgentSessionInfo
        if (!sessionId.contentEquals(other.sessionId)) return false
        if (!serverHostKey.contentEquals(other.serverHostKey)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = sessionId.contentHashCode()
        result = 31 * result + serverHostKey.contentHashCode()
        return result
    }
}
