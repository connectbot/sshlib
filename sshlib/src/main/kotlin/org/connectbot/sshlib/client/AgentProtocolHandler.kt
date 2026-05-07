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
import org.connectbot.sshlib.AgentIdentity
import org.connectbot.sshlib.AgentKeySpec
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AgentSigningContext
import org.connectbot.sshlib.DestinationConstraint
import org.connectbot.sshlib.crypto.SignatureVerifier
import org.connectbot.sshlib.protocol.SshAgentIdentitiesAnswer
import org.connectbot.sshlib.protocol.SshAgentMessage
import org.connectbot.sshlib.protocol.SshAgentSignResponse
import org.connectbot.sshlib.protocol.SshAgentcExtension
import org.connectbot.sshlib.protocol.SshAgentcSessionBind
import org.connectbot.sshlib.protocol.SshAgentcSignRequest
import org.connectbot.sshlib.protocol.UserauthPublickeySignatureDataAny
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.slf4j.LoggerFactory

internal fun interface SessionBindVerifier {
    fun verify(hostKeyBlob: ByteArray, signature: ByteArray, data: ByteArray): Boolean
}

internal data class BindingEntry(val hostKeyBlob: ByteArray, val sessionId: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as BindingEntry
        if (!hostKeyBlob.contentEquals(other.hostKeyBlob)) return false
        if (!sessionId.contentEquals(other.sessionId)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = hostKeyBlob.contentHashCode()
        result = 31 * result + sessionId.contentHashCode()
        return result
    }
}

internal data class SignedDataComponents(
    val methodName: String,
    val destUsername: String,
    val serverHostKeyBlob: ByteArray?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SignedDataComponents
        if (methodName != other.methodName) return false
        if (destUsername != other.destUsername) return false
        if (!(serverHostKeyBlob == null && other.serverHostKeyBlob == null) &&
            (
                serverHostKeyBlob == null || other.serverHostKeyBlob == null ||
                    !serverHostKeyBlob.contentEquals(other.serverHostKeyBlob)
                )
        ) {
            return false
        }
        return true
    }

    override fun hashCode(): Int {
        var result = methodName.hashCode()
        result = 31 * result + destUsername.hashCode()
        result = 31 * result + (serverHostKeyBlob?.contentHashCode() ?: 0)
        return result
    }
}

internal fun buildAgentMessage(messageType: Int, payload: ByteArray): ByteArray {
    val totalLength = 1L + payload.size
    val stream = ByteBufferKaitaiStream(4 + totalLength)
    stream.writeU4be(totalLength)
    stream.writeU1(messageType)
    stream.writeBytes(payload)
    stream.seek(0)
    return stream.readBytesFull()
}

internal fun isConstraintSatisfied(
    constraints: List<DestinationConstraint>,
    components: SignedDataComponents,
    bindingList: List<BindingEntry>,
): Boolean {
    val isForwarding = bindingList.isNotEmpty()
    val forwardingHopKey = if (bindingList.size >= 2) {
        bindingList[bindingList.size - 2].hostKeyBlob
    } else if (bindingList.size == 1) {
        bindingList[0].hostKeyBlob
    } else {
        null
    }

    return constraints.any { c ->
        val fromMatches = if (!isForwarding) {
            c.fromHostname.isEmpty() && c.fromKeyspecs.isEmpty()
        } else {
            forwardingHopKey != null && c.fromKeyspecs.any { spec ->
                spec.keyBlob.contentEquals(forwardingHopKey)
            }
        }
        if (!fromMatches) return@any false

        val usernameMatches = c.toUsername.isEmpty() || c.toUsername == components.destUsername
        if (!usernameMatches) return@any false

        val hostKeyMatches = components.serverHostKeyBlob != null &&
            c.toHostspecs.any { spec -> spec.keyBlob.contentEquals(components.serverHostKeyBlob) }
        hostKeyMatches
    }
}

internal class AgentProtocolHandler(
    private val provider: AgentProvider,
    private val sessionInfo: AgentSessionInfo,
    private val bindVerifier: SessionBindVerifier = SessionBindVerifier { hk, sig, data ->
        SignatureVerifier.verify(hk, sig, data)
    },
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

        private const val METHOD_PUBLICKEY_HOSTBOUND = "publickey-hostbound-v00@openssh.com"
    }

    private val bindingList: MutableList<BindingEntry> = mutableListOf()

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

        val allIdentities = provider.getIdentities()
        val visibleIdentities = filterVisibleIdentities(allIdentities)
        logger.debug("Provider returned ${allIdentities.size} identities, ${visibleIdentities.size} visible for current path")

        val response = SshAgentIdentitiesAnswer()
        response.setNkeys(visibleIdentities.size.toLong())

        val identityList = ArrayList<SshAgentIdentitiesAnswer.Identity>()
        for (identity in visibleIdentities) {
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

    private fun filterVisibleIdentities(identities: List<AgentIdentity>): List<AgentIdentity> {
        if (bindingList.isEmpty()) return identities
        val lastHopKey = bindingList.last().hostKeyBlob
        return identities.filter { identity ->
            val constraints = identity.destinationConstraints
            if (constraints == null) return@filter true
            constraints.any { c ->
                c.fromKeyspecs.isNotEmpty() && c.fromKeyspecs.any { spec ->
                    spec.keyBlob.contentEquals(lastHopKey)
                }
            }
        }
    }

    private suspend fun handleSignRequest(message: SshAgentMessage): ByteArray {
        logger.debug("Handling SIGN_REQUEST")

        val payload = parsePayload<SshAgentcSignRequest>(message)
        val keyBlob = payload.keyBlob().data()
        val dataToSign = payload.data().data()

        val identity = provider.getIdentities().find { it.publicKeyBlob.contentEquals(keyBlob) }
        val constraints = identity?.destinationConstraints

        if (constraints != null) {
            var components = parseSignedDataComponents(dataToSign)
            if (components == null) {
                logger.warn("Failed to parse signed data for constraint check")
                return createFailureResponse()
            }

            if (bindingList.isNotEmpty() && components.methodName != METHOD_PUBLICKEY_HOSTBOUND) {
                logger.warn("Forwarded connection requires publickey-hostbound method, got: ${components.methodName}")
                return createFailureResponse()
            }

            if (bindingList.isEmpty() && components.serverHostKeyBlob == null) {
                components = components.copy(serverHostKeyBlob = sessionInfo.serverHostKey)
            }

            if (!isConstraintSatisfied(constraints, components, bindingList)) {
                logger.warn("Destination constraint not satisfied for key")
                return createFailureResponse()
            }
        }

        val isBound = bindingList.isNotEmpty()
        val effectiveSessionId = bindingList.lastOrNull()?.sessionId ?: sessionInfo.sessionId

        val context = AgentSigningContext(
            publicKeyBlob = keyBlob,
            dataToSign = dataToSign,
            flags = payload.flags().toInt(),
            sessionId = effectiveSessionId,
            serverHostKey = sessionInfo.serverHostKey,
            isBound = isBound,
        )

        logger.debug("Requesting signature from provider (bound=$isBound, flags=${context.flags})")

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

    private fun parseSignedDataComponents(data: ByteArray): SignedDataComponents? = try {
        val stream = ByteBufferKaitaiStream(data)
        val sigData = UserauthPublickeySignatureDataAny(stream)
        sigData._read()

        SignedDataComponents(
            methodName = sigData.methodName().value(),
            destUsername = sigData.userName().value(),
            serverHostKeyBlob = sigData.serverHostKey()?.data(),
        )
    } catch (e: Exception) {
        logger.debug("Failed to parse signed data components: ${e.message}")
        null
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

        val hostKeyBlob = bind.hostkey().data()
        val sessionId = bind.sessionIdentifier().data()
        val isForwarding = bind.isForwarding() != 0

        if (bindingList.any { it.sessionId.contentEquals(sessionId) }) {
            logger.warn("Session bind replay: session ID already recorded")
            return createFailureResponse()
        }

        if (!isForwarding && !hostKeyBlob.contentEquals(sessionInfo.serverHostKey)) {
            logger.error("Session bind hostkey mismatch for non-forwarding bind")
            return createFailureResponse()
        }

        if (!bindVerifier.verify(hostKeyBlob, bind.signature().data(), sessionId)) {
            logger.error("Session bind signature verification failed")
            return createFailureResponse()
        }

        bindingList.add(BindingEntry(hostKeyBlob, sessionId))
        logger.info("Session binding successful (isForwarding=$isForwarding, total bindings=${bindingList.size})")
        return createSuccessResponse()
    }

    private inline fun <reified T : KaitaiStruct.ReadWrite> parsePayload(message: SshAgentMessage): T {
        val stream = ByteBufferKaitaiStream(message._raw_payload())
        val payload = T::class.java.getConstructor(io.kaitai.struct.KaitaiStream::class.java).newInstance(stream)
        payload._read()
        return payload
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
