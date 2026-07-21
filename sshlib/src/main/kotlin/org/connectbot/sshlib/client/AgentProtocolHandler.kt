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

package org.connectbot.sshlib.client

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStream
import io.kaitai.struct.KaitaiStruct
import org.connectbot.sshlib.AgentIdentity
import org.connectbot.sshlib.AgentKeySpec
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AgentResult
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
import java.util.concurrent.CancellationException

internal fun interface SessionBindVerifier {
    fun verify(hostKeyBlob: ByteArray, signature: ByteArray, data: ByteArray): Boolean
}

internal const val AGENT_MAX_SESSION_ID_LENGTH = 128

internal sealed interface AgentParseResult<out T> {
    data class Success<T>(val value: T) : AgentParseResult<T>

    data class Failure(
        val message: String,
        val cause: Throwable? = null,
    ) : AgentParseResult<Nothing>
}

internal data class BindingEntry(
    val hostKeyBlob: ByteArray,
    val sessionId: ByteArray,
    val isForwarding: Boolean = false,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as BindingEntry
        if (!hostKeyBlob.contentEquals(other.hostKeyBlob)) return false
        if (!sessionId.contentEquals(other.sessionId)) return false
        if (isForwarding != other.isForwarding) return false
        return true
    }

    override fun hashCode(): Int {
        var result = hostKeyBlob.contentHashCode()
        result = 31 * result + sessionId.contentHashCode()
        result = 31 * result + isForwarding.hashCode()
        return result
    }
}

internal data class SignedDataComponents(
    val methodName: String,
    val destUsername: String,
    val serverHostKeyBlob: ByteArray?,
    val sessionId: ByteArray = ByteArray(0),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SignedDataComponents
        if (methodName != other.methodName) return false
        if (destUsername != other.destUsername) return false
        if (!sessionId.contentEquals(other.sessionId)) return false
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
        result = 31 * result + sessionId.contentHashCode()
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
    bindingList: List<BindingEntry>,
    destinationUsername: String?,
): Boolean {
    if (bindingList.isEmpty()) return false

    fun keyMatches(specs: List<AgentKeySpec>, key: ByteArray): Boolean = specs.any { !it.isCa && it.keyBlob.contentEquals(key) }

    fun edgeMatches(
        fromKey: ByteArray?,
        toKey: ByteArray?,
        username: String?,
    ): Boolean = constraints.any { constraint ->
        val fromMatches = if (fromKey == null) {
            constraint.fromHostname.isEmpty() && constraint.fromKeyspecs.isEmpty()
        } else {
            keyMatches(constraint.fromKeyspecs, fromKey)
        }
        if (!fromMatches) return@any false

        if (username != null &&
            constraint.toUsername.isNotEmpty() &&
            constraint.toUsername != username
        ) {
            return@any false
        }

        toKey == null || keyMatches(constraint.toHostspecs, toKey)
    }

    for (index in bindingList.indices) {
        val binding = bindingList[index]
        val isLast = index == bindingList.lastIndex

        if (!isLast && !binding.isForwarding) return false
        if (isLast && destinationUsername != null && binding.isForwarding) return false

        val fromKey = bindingList.getOrNull(index - 1)?.hostKeyBlob
        val username = destinationUsername.takeIf { isLast }
        if (!edgeMatches(fromKey, binding.hostKeyBlob, username)) return false
    }

    // A forwarding-only final binding may list a constrained identity only if
    // at least one permitted next hop starts at that host.
    if (destinationUsername == null && bindingList.last().isForwarding) {
        if (!edgeMatches(bindingList.last().hostKeyBlob, null, null)) {
            return false
        }
    }

    return true
}

internal class AgentProtocolHandler(
    private val provider: AgentProvider,
    private val sessionInfo: AgentSessionInfo,
    private val bindVerifier: SessionBindVerifier = SessionBindVerifier { hk, sig, data ->
        SignatureVerifier.verifyWithKeyType(hk, sig, data)
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

        private const val MAX_BINDINGS = 16
        private const val SERVICE_CONNECTION = "ssh-connection"
        private const val METHOD_PUBLICKEY = "publickey"
        private const val METHOD_PUBLICKEY_HOSTBOUND = "publickey-hostbound-v00@openssh.com"
        private const val KEY_TYPE_SSH_RSA = "ssh-rsa"
        private const val KEY_TYPE_SSH_RSA_CERT = "ssh-rsa-cert-v01@openssh.com"
    }

    private val bindingList: MutableList<BindingEntry> = mutableListOf<BindingEntry>().apply {
        if (sessionInfo.sessionId.isNotEmpty() &&
            sessionInfo.sessionId.size <= AGENT_MAX_SESSION_ID_LENGTH &&
            sessionInfo.serverHostKey.isNotEmpty()
        ) {
            add(
                BindingEntry(
                    hostKeyBlob = sessionInfo.serverHostKey.copyOf(),
                    sessionId = sessionInfo.sessionId.copyOf(),
                    isForwarding = true,
                ),
            )
        }
    }

    suspend fun handleRequest(requestBytes: ByteArray): ByteArray = try {
        logger.debug("Handling agent request (${requestBytes.size} bytes)")

        val message = when (val result = parseAgentMessage(requestBytes)) {
            is AgentParseResult.Success -> result.value

            is AgentParseResult.Failure -> {
                logParseFailure(result)
                return createFailureResponse()
            }
        }

        val messageType = message.messageType()
        logger.debug("Agent message type: $messageType")

        when (messageType) {
            SSH_AGENTC_REQUEST_IDENTITIES -> handleRequestIdentities()

            SSH_AGENTC_SIGN_REQUEST -> handleSignRequest(message)

            SSH_AGENTC_EXTENSION -> handleExtension(message)

            else -> {
                logger.warn("Unknown agent message type: $messageType")
                createFailureResponse()
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        logger.error("Agent request failed without a protocol response", e)
        createFailureResponse()
    }

    private suspend fun handleRequestIdentities(): ByteArray {
        logger.debug("Handling REQUEST_IDENTITIES")

        val allIdentities = when (val result = getProviderIdentities()) {
            is AgentResult.Success -> result.value

            is AgentResult.Failure -> {
                logProviderFailure("get identities", result)
                return createFailureResponse()
            }
        }
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
        return identities.filter { identity ->
            val constraints = identity.destinationConstraints
            if (constraints == null) return@filter true
            isConstraintSatisfied(constraints, bindingList, destinationUsername = null)
        }
    }

    private suspend fun handleSignRequest(message: SshAgentMessage): ByteArray {
        logger.debug("Handling SIGN_REQUEST")

        val payload = when (val result = parsePayload<SshAgentcSignRequest>(message)) {
            is AgentParseResult.Success -> result.value

            is AgentParseResult.Failure -> {
                logParseFailure(result)
                return createFailureResponse()
            }
        }
        val keyBlob = payload.keyBlob().data()
        val dataToSign = payload.data().data()

        val identities = when (val result = getProviderIdentities()) {
            is AgentResult.Success -> result.value

            is AgentResult.Failure -> {
                logProviderFailure("get identities for signing", result)
                return createFailureResponse()
            }
        }
        val identity = identities.find { it.publicKeyBlob.contentEquals(keyBlob) }
        if (identity == null) {
            logger.warn("Refusing signing request for an identity not exposed by the provider")
            return createFailureResponse()
        }
        val constraints = identity.destinationConstraints

        if (constraints != null) {
            val components = when (val result = parseSignedDataComponents(dataToSign, keyBlob)) {
                is AgentParseResult.Success -> result.value

                is AgentParseResult.Failure -> {
                    logParseFailure(result)
                    return createFailureResponse()
                }
            }

            val latestBinding = bindingList.lastOrNull()
            if (latestBinding == null) {
                logger.warn("Refusing constrained signing without a trusted session binding")
                return createFailureResponse()
            }
            if (!components.sessionId.contentEquals(latestBinding.sessionId)) {
                logger.warn("Signed session ID does not match the active session binding")
                return createFailureResponse()
            }

            if (bindingList.size > 1 && components.methodName != METHOD_PUBLICKEY_HOSTBOUND) {
                logger.warn("Forwarded connection requires publickey-hostbound method, got: ${components.methodName}")
                return createFailureResponse()
            }

            if (components.serverHostKeyBlob == null ||
                !components.serverHostKeyBlob.contentEquals(latestBinding.hostKeyBlob)
            ) {
                logger.warn("Signed server host key does not match the active session binding")
                return createFailureResponse()
            }

            if (!isConstraintSatisfied(constraints, bindingList, components.destUsername)) {
                logger.warn("Destination constraint not satisfied for key")
                return createFailureResponse()
            }
        }

        val isBound = bindingList.isNotEmpty()
        val effectiveSessionId = bindingList.lastOrNull()?.sessionId ?: sessionInfo.sessionId
        val effectiveServerHostKey = bindingList.lastOrNull()?.hostKeyBlob ?: sessionInfo.serverHostKey

        val context = AgentSigningContext(
            publicKeyBlob = keyBlob.copyOf(),
            dataToSign = dataToSign.copyOf(),
            flags = payload.flags().toInt(),
            sessionId = effectiveSessionId.copyOf(),
            serverHostKey = effectiveServerHostKey.copyOf(),
            isBound = isBound,
        )

        logger.debug("Requesting signature from provider (bound=$isBound, flags=${context.flags})")

        val signature = when (val result = signWithProvider(context)) {
            is AgentResult.Success -> result.value

            is AgentResult.Failure -> {
                logProviderFailure("sign data", result)
                return createFailureResponse()
            }
        }

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

    private fun parseSignedDataComponents(
        data: ByteArray,
        expectedPublicKeyBlob: ByteArray,
    ): AgentParseResult<SignedDataComponents> {
        val parsed = parseAgentInput("Malformed public-key authentication data") {
            val stream = ByteBufferKaitaiStream(data)
            val sigData = UserauthPublickeySignatureDataAny(stream)
            sigData._read()
            sigData to stream.isEof
        }
        val (sigData, isFullyConsumed) = when (parsed) {
            is AgentParseResult.Success -> parsed.value
            is AgentParseResult.Failure -> return parsed
        }

        val serviceName = sigData.serviceName().value()
        val methodName = sigData.methodName().value()
        val algorithmName = sigData.publicKeyAlgorithmName().value()
        val embeddedPublicKey = sigData.publicKeyBlob().data()
        val keyType = keyBlobAlgorithmName(expectedPublicKeyBlob)
        val algorithmMatches = when (keyType) {
            KEY_TYPE_SSH_RSA ->
                algorithmName == KEY_TYPE_SSH_RSA ||
                    algorithmName == "rsa-sha2-256" ||
                    algorithmName == "rsa-sha2-512"

            KEY_TYPE_SSH_RSA_CERT ->
                algorithmName == KEY_TYPE_SSH_RSA_CERT ||
                    algorithmName == "rsa-sha2-256-cert-v01@openssh.com" ||
                    algorithmName == "rsa-sha2-512-cert-v01@openssh.com"

            null -> false

            else -> algorithmName == keyType
        }

        if (!isFullyConsumed ||
            serviceName != SERVICE_CONNECTION ||
            (methodName != METHOD_PUBLICKEY && methodName != METHOD_PUBLICKEY_HOSTBOUND) ||
            !embeddedPublicKey.contentEquals(expectedPublicKeyBlob) ||
            !algorithmMatches
        ) {
            return AgentParseResult.Failure("Inconsistent public-key authentication data")
        }

        return AgentParseResult.Success(
            SignedDataComponents(
                methodName = methodName,
                destUsername = sigData.userName().value(),
                serverHostKeyBlob = sigData.serverHostKey()?.data(),
                sessionId = sigData.sessionIdentifier().data(),
            ),
        )
    }

    private suspend fun handleExtension(message: SshAgentMessage): ByteArray {
        logger.debug("Handling EXTENSION")

        val ext = when (val result = parsePayload<SshAgentcExtension>(message)) {
            is AgentParseResult.Success -> result.value

            is AgentParseResult.Failure -> {
                logParseFailure(result)
                return createFailureResponse()
            }
        }
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
        val parsed = parseAgentInput("Malformed session-bind extension") {
            val stream = ByteBufferKaitaiStream(extensionData)
            val bind = SshAgentcSessionBind(stream)
            bind._read()
            bind to stream.isEof
        }
        val (bind, isFullyConsumed) = when (parsed) {
            is AgentParseResult.Success -> parsed.value

            is AgentParseResult.Failure -> {
                logParseFailure(parsed)
                return createFailureResponse()
            }
        }

        val hostKeyBlob = bind.hostkey().data()
        val sessionId = bind.sessionIdentifier().data()
        val isForwarding = bind.isForwarding() != 0

        if (!isFullyConsumed) {
            logger.warn("Session bind request contains trailing data")
            return createFailureResponse()
        }
        if (sessionId.isEmpty() || sessionId.size > AGENT_MAX_SESSION_ID_LENGTH) {
            logger.warn("Session bind identifier has invalid length: ${sessionId.size}")
            return createFailureResponse()
        }
        if (bindingList.size >= MAX_BINDINGS) {
            logger.warn("Too many session bindings")
            return createFailureResponse()
        }
        if (bindingList.lastOrNull()?.isForwarding == false) {
            logger.warn("Session binding already finalized for authentication")
            return createFailureResponse()
        }
        if (bindingList.any { it.sessionId.contentEquals(sessionId) }) {
            logger.warn("Session bind replay: session ID already recorded")
            return createFailureResponse()
        }
        val verified = try {
            bindVerifier.verify(hostKeyBlob, bind.signature().data(), sessionId)
        } catch (e: Exception) {
            logger.warn("Session bind verifier failed", e)
            false
        }
        if (!verified) {
            logger.error("Session bind signature verification failed")
            return createFailureResponse()
        }

        bindingList.add(
            BindingEntry(hostKeyBlob.copyOf(), sessionId.copyOf(), isForwarding),
        )
        logger.info("Session binding successful (isForwarding=$isForwarding, total bindings=${bindingList.size})")
        return createSuccessResponse()
    }

    private fun parseAgentMessage(requestBytes: ByteArray): AgentParseResult<SshAgentMessage> = parseAgentInput("Malformed SSH agent request") {
        val stream = ByteBufferKaitaiStream(requestBytes)
        val message = SshAgentMessage(stream)
        message._read()
        message
    }

    private inline fun <reified T : KaitaiStruct.ReadWrite> parsePayload(
        message: SshAgentMessage,
    ): AgentParseResult<T> = parseAgentInput("Malformed SSH agent payload") {
        val stream = ByteBufferKaitaiStream(message._raw_payload())
        val payload = T::class.java.getConstructor(KaitaiStream::class.java).newInstance(stream)
        payload._read()
        payload
    }

    private inline fun <T> parseAgentInput(
        description: String,
        parse: () -> T,
    ): AgentParseResult<T> = try {
        AgentParseResult.Success(parse())
    } catch (e: Exception) {
        AgentParseResult.Failure(description, e)
    }

    private suspend fun getProviderIdentities(): AgentResult<List<AgentIdentity>> = callProvider("Agent provider threw while retrieving identities") {
        provider.getIdentities()
    }

    private suspend fun signWithProvider(context: AgentSigningContext): AgentResult<ByteArray?> = callProvider("Agent provider threw while signing") {
        provider.signData(context)
    }

    private suspend inline fun <T> callProvider(
        failureMessage: String,
        callback: suspend () -> AgentResult<T>,
    ): AgentResult<T> = try {
        callback()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        AgentResult.Failure(failureMessage, e)
    }

    private fun logParseFailure(failure: AgentParseResult.Failure) {
        logger.warn(failure.message, failure.cause)
    }

    private fun logProviderFailure(operation: String, failure: AgentResult.Failure) {
        logger.warn("Agent provider failed to $operation: ${failure.message}", failure.cause)
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
