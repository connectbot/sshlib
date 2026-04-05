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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.crypto.CipherEntry
import org.connectbot.sshlib.crypto.CompressionEntry
import org.connectbot.sshlib.crypto.DiffieHellmanGroupExchange
import org.connectbot.sshlib.crypto.EncryptionInstance
import org.connectbot.sshlib.crypto.KexAlgorithm
import org.connectbot.sshlib.crypto.KexEntry
import org.connectbot.sshlib.crypto.KexType
import org.connectbot.sshlib.crypto.KeyDerivation
import org.connectbot.sshlib.crypto.MacEntry
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.crypto.SignatureVerifier
import org.connectbot.sshlib.crypto.SshPrivateKey
import org.connectbot.sshlib.crypto.SshPublicKeyEncoder
import org.connectbot.sshlib.protocol.AsciiString
import org.connectbot.sshlib.protocol.ChannelOpenDirectTcpip
import org.connectbot.sshlib.protocol.ChannelOpenForwardedTcpip
import org.connectbot.sshlib.protocol.ChannelOpenSession
import org.connectbot.sshlib.protocol.GlobalRequestCancelTcpipForward
import org.connectbot.sshlib.protocol.GlobalRequestResponseTcpipForward
import org.connectbot.sshlib.protocol.GlobalRequestTcpipForward
import org.connectbot.sshlib.protocol.IdBanner
import org.connectbot.sshlib.protocol.KexDhGexPayload
import org.connectbot.sshlib.protocol.KexEcdhPayload
import org.connectbot.sshlib.protocol.KexdhPayload
import org.connectbot.sshlib.protocol.SshClientCallbacks
import org.connectbot.sshlib.protocol.SshClientStateMachine
import org.connectbot.sshlib.protocol.SshEnums
import org.connectbot.sshlib.protocol.SshMsgChannelClose
import org.connectbot.sshlib.protocol.SshMsgChannelData
import org.connectbot.sshlib.protocol.SshMsgChannelEof
import org.connectbot.sshlib.protocol.SshMsgChannelExtendedData
import org.connectbot.sshlib.protocol.SshMsgChannelOpen
import org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation
import org.connectbot.sshlib.protocol.SshMsgChannelOpenFailure
import org.connectbot.sshlib.protocol.SshMsgChannelRequest
import org.connectbot.sshlib.protocol.SshMsgChannelWindowAdjust
import org.connectbot.sshlib.protocol.SshMsgDebug
import org.connectbot.sshlib.protocol.SshMsgDisconnect
import org.connectbot.sshlib.protocol.SshMsgGlobalRequest
import org.connectbot.sshlib.protocol.SshMsgKexDhGexGroup
import org.connectbot.sshlib.protocol.SshMsgKexDhGexInit
import org.connectbot.sshlib.protocol.SshMsgKexDhGexReply
import org.connectbot.sshlib.protocol.SshMsgKexDhGexRequest
import org.connectbot.sshlib.protocol.SshMsgKexEcdhInit
import org.connectbot.sshlib.protocol.SshMsgKexEcdhReply
import org.connectbot.sshlib.protocol.SshMsgKexdhInit
import org.connectbot.sshlib.protocol.SshMsgKexdhReply
import org.connectbot.sshlib.protocol.SshMsgKexinit
import org.connectbot.sshlib.protocol.SshMsgServiceAccept
import org.connectbot.sshlib.protocol.SshMsgServiceRequest
import org.connectbot.sshlib.protocol.SshMsgUserauthBanner
import org.connectbot.sshlib.protocol.SshMsgUserauthFailure
import org.connectbot.sshlib.protocol.SshMsgUserauthInfoRequest
import org.connectbot.sshlib.protocol.SshMsgUserauthInfoResponse
import org.connectbot.sshlib.protocol.SshMsgUserauthPkOk
import org.connectbot.sshlib.protocol.SshMsgUserauthRequest
import org.connectbot.sshlib.protocol.UnencryptedPacket
import org.connectbot.sshlib.protocol.UserauthPublickeySignatureData
import org.connectbot.sshlib.protocol.UserauthRequestKeyboardInteractive
import org.connectbot.sshlib.protocol.UserauthRequestNone
import org.connectbot.sshlib.protocol.UserauthRequestPassword
import org.connectbot.sshlib.protocol.UserauthRequestPublickey
import org.connectbot.sshlib.protocol.createAsciiString
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.createMpint
import org.connectbot.sshlib.protocol.createNameList
import org.connectbot.sshlib.protocol.createUtf8String
import org.connectbot.sshlib.protocol.toByteArray
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.Transport
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * SSH connection handler that manages the protocol flow.
 *
 * This class ties together the state machine, transport layer, and crypto
 * implementations to handle a complete SSH connection lifecycle.
 *
 * @param transport Underlying transport (e.g., TCP socket)
 * @param clientVersion Client version string (default: SSH-2.0-CBSSH_1.0)
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SshConnection(
    private val transport: Transport,
    private val clientVersion: String = "SSH-2.0-CBSSH_1.0",
    private val hostKeyVerifier: HostKeyVerifier,
    private val kexAlgorithms: String = KexEntry.defaultString,
    private val hostKeyAlgorithms: String = SignatureEntry.defaultString,
    private val encryptionAlgorithms: String = CipherEntry.defaultString,
    private val macAlgorithms: String = MacEntry.defaultString,
    private val compressionAlgorithms: String = CompressionEntry.defaultString,
    private val preferPasswordAuth: Boolean = false,
) {

    companion object {
        private val logger = LoggerFactory.getLogger(SshConnection::class.java)
    }

    private val packetIO = PacketIO(transport)

    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
    private val stateMachineDispatcher = newSingleThreadContext("ssh-state-machine")

    private val callbacks = object : SshClientCallbacks {
        override fun sendVersion() = this@SshConnection.sendVersion()
        override fun receiveVersion(banner: IdBanner) = this@SshConnection.receiveVersion(banner)
        override suspend fun sendKexInit() = this@SshConnection.sendKexInit()
        override fun receiveKexInit(msg: SshMsgKexinit) = this@SshConnection.receiveKexInit(msg)
        override suspend fun sendKexExchangeInit() = this@SshConnection.sendKexExchangeInit()
        override suspend fun receiveKexDhReply(msg: SshMsgKexdhReply) = this@SshConnection.receiveKexDhReply(msg)
        override suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) = this@SshConnection.receiveKexEcdhReply(msg)
        override suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) = this@SshConnection.receiveKexDhGexReply(msg)
        override suspend fun sendNewKeys() = this@SshConnection.sendNewKeys()
        override fun receiveNewKeys() = this@SshConnection.receiveNewKeys()
        override fun activateEncryption() = this@SshConnection.activateEncryption()
        override suspend fun sendServiceRequest(service: String) = this@SshConnection.sendServiceRequest(service)
        override fun receiveServiceAccept(service: String) = this@SshConnection.receiveServiceAccept(service)
        override fun startAuthentication() = this@SshConnection.startAuthentication()
        override fun authenticationSuccess() = this@SshConnection.authenticationSuccess()
        override fun authenticationFailure() = this@SshConnection.authenticationFailure()
        override fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest) = this@SshConnection.receiveUserauthInfoRequest(msg)
        override fun receiveUserauthBanner(msg: SshMsgUserauthBanner) = this@SshConnection.receiveUserauthBanner(msg)
        override suspend fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int) = this@SshConnection.sendChannelOpen(channelType, localChannelNumber, initialWindowSize, maxPacketSize)
        override fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) = this@SshConnection.receiveChannelOpenConfirmation(msg)
        override fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) = this@SshConnection.receiveChannelOpenFailure(msg)
        override suspend fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) = this@SshConnection.sendChannelRequest(recipientChannel, requestType, wantReply, message)
        override fun receiveChannelSuccess() = this@SshConnection.receiveChannelSuccess()
        override fun receiveChannelFailure() = this@SshConnection.receiveChannelFailure()
        override suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest) = this@SshConnection.receiveGlobalRequest(msg)
        override fun debug(msg: SshMsgDebug) = this@SshConnection.debug(msg)
        override fun ignore() = this@SshConnection.ignore()
        override suspend fun disconnect() = this@SshConnection.disconnect()
        override fun onStateEnter(stateName: String) = this@SshConnection.onStateEnter(stateName)
        override fun onStateExit(stateName: String) = this@SshConnection.onStateExit(stateName)
    }

    private val stateMachine = SshClientStateMachine(callbacks)
    private val connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _disconnectedFlow = MutableSharedFlow<Throwable?>(extraBufferCapacity = 1)
    val disconnectedFlow: SharedFlow<Throwable?> = _disconnectedFlow.asSharedFlow()

    private var serverVersion: String? = null
    private var clientKexInit: ByteArray? = null
    private var serverKexInit: ByteArray? = null

    private var kex: KexAlgorithm? = null
    private var clientPublicKey: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var exchangeHash: ByteArray? = null
    private var sessionId: ByteArray? = null

    private var negotiatedKex: String? = null
    private var negotiatedEncryptionC2S: String? = null
    private var negotiatedEncryptionS2C: String? = null
    private var negotiatedMacC2S: String? = null
    private var negotiatedMacS2C: String? = null
    private var negotiatedCompressionC2S: String? = null
    private var negotiatedCompressionS2C: String? = null
    private var strictKexEnabled: Boolean = false

    private var nextLocalChannelNumber = 0
    private val channelNumberLock = Mutex()
    private val channels = ConcurrentHashMap<Int, SessionChannel>()
    private val channelsByRemote = ConcurrentHashMap<Int, SessionChannel>()
    private val agentChannels = ConcurrentHashMap<Int, AgentChannel>()
    private val agentChannelsByRemote = ConcurrentHashMap<Int, AgentChannel>()
    private val forwardingChannels = ConcurrentHashMap<Int, ForwardingChannel>()
    private val forwardingChannelsByRemote = ConcurrentHashMap<Int, ForwardingChannel>()

    private var agentProvider: AgentProvider? = null
    private var serverHostKeyBlob: ByteArray? = null

    /**
     * Helper to manage a pending asynchronous operation that waits for a server response.
     * Ensures all state changes happen on the [stateMachineDispatcher].
     */
    private inner class PendingValue<T> {
        @Volatile
        private var deferred: CompletableDeferred<T>? = null

        suspend fun set(value: CompletableDeferred<T>) {
            withContext(stateMachineDispatcher) {
                deferred = value
            }
        }

        /**
         * Set the deferred directly. Must only be called from within [stateMachineDispatcher].
         */
        fun setDirect(value: CompletableDeferred<T>) {
            deferred = value
        }

        /**
         * Complete the pending deferred. Must only be called from within [stateMachineDispatcher]
         * to ensure atomicity of the read-then-clear sequence.
         * @return true if there was a pending deferred to complete, false if none was set.
         */
        fun complete(value: T): Boolean {
            val p = deferred ?: return false
            deferred = null
            p.complete(value)
            return true
        }

        /**
         * Fail the pending deferred. Must only be called from within [stateMachineDispatcher]
         * to ensure atomicity of the read-then-clear sequence.
         */
        fun completeExceptionally(e: Throwable) {
            val p = deferred
            deferred = null
            p?.completeExceptionally(e)
        }

        suspend fun clearIfSame(expected: CompletableDeferred<T>) {
            withContext(stateMachineDispatcher) {
                if (deferred === expected) {
                    deferred = null
                }
            }
        }
    }

    // Pending async operations - completed by callbacks
    private val pendingAuth = PendingValue<Boolean>()
    private val pendingChannelOpen = PendingValue<SshMsgChannelOpenConfirmation?>()
    private class PendingChannelOpen(
        val deferred: CompletableDeferred<ForwardingChannel?>,
        val maxPacketSize: Int,
        val initialWindowSize: Int,
    )
    private val pendingChannelOpens = ConcurrentHashMap<Int, PendingChannelOpen>()
    private val pendingChannelRequest = PendingValue<Boolean>()
    private val pendingGlobalRequest = PendingValue<ByteArray?>()

    private val remoteForwarders = ConcurrentHashMap<String, suspend (connectedAddr: String, connectedPort: Int, originAddr: String, originPort: Int, senderChannel: Int, initialWindow: Long, maxPacketSize: Int) -> Unit>()

    private var infoRequestChannel: Channel<SshMsgUserauthInfoRequest>? = null

    // Strategy-based authentication state
    @Volatile private var authResultChannel: Channel<AuthResult>? = null

    @Volatile private var allowedAuthentications: Set<String>? = null

    @Volatile private var currentAuthMethod: AuthMethod? = null
    private val triedPublicKeys: MutableSet<AuthPublicKey> = Collections.synchronizedSet(mutableSetOf())

    private var packetLoopJob: Job? = null

    private suspend fun dispatchEvent(event: SshClientStateMachine.SshEvent) {
        logger.debug("Dispatching event: $event")
        try {
            withContext(stateMachineDispatcher) {
                stateMachine.processEvent(event)
            }
        } catch (e: Exception) {
            logger.error("State machine failed to process event: $event", e)
            throw e
        }
    }

    /**
     * Serialized write to the transport through the state machine dispatcher.
     */
    private suspend fun writePacket(messageType: Int, payload: ByteArray = byteArrayOf()) {
        withContext(stateMachineDispatcher) {
            packetIO.writePacket(messageType, payload)
        }
    }

    /**
     * Initiate SSH connection.
     * This returns when authentication is complete.
     */
    suspend fun connect(): Boolean {
        try {
            dispatchEvent(SshClientStateMachine.SshEvent.Connect)

            // Version exchange
            packetIO.writeBanner(clientVersion)
            val banner = packetIO.readBanner()
            dispatchEvent(SshClientStateMachine.SshEvent.ReceiveVersion(banner))

            // Key exchange initialization - read server's KEXINIT
            val kexInitPacket = packetIO.readPacket()
            val kexInit = kexInitPacket.body() as SshMsgKexinit

            // Save raw KEXINIT payload for exchange hash (message type + body)
            val kexInitMsgType = kexInitPacket.messageType().id().toByte()
            serverKexInit = byteArrayOf(kexInitMsgType) + kexInitPacket._raw_body()

            dispatchEvent(SshClientStateMachine.SshEvent.ReceiveKexInit(kexInit))
            // Note: ReceiveKexInit transition triggers sendKexInit() via state machine

            // Key exchange - read server's reply
            // KEX-specific messages (30-49) need special parsing based on negotiated algorithm
            val kexReplyPacket = packetIO.readPacket()
            val messageTypeByte = kexReplyPacket.messageType().id().toByte()
            val rawBody = byteArrayOf(messageTypeByte) + kexReplyPacket._raw_body()

            val negotiated = negotiatedKex
                ?: throw SshException("No KEX algorithm negotiated")
            val kexEntry = KexEntry.fromSshName(negotiated)
                ?: throw SshException("Unknown KEX algorithm: $negotiated")
            when (kexEntry.type) {
                KexType.ECDH -> {
                    val ecdhStream = ByteBufferKaitaiStream(rawBody)
                    val ecdhPayload = KexEcdhPayload(ecdhStream)
                    ecdhPayload._read()
                    val ecdhReply = ecdhPayload.body() as SshMsgKexEcdhReply
                    dispatchEvent(SshClientStateMachine.SshEvent.ReceiveKex.EcdhReply(ecdhReply))
                }

                KexType.DH -> {
                    val kexdhStream = ByteBufferKaitaiStream(rawBody)
                    val kexdhPayload = KexdhPayload(kexdhStream)
                    kexdhPayload._read()
                    val dhReply = kexdhPayload.body() as SshMsgKexdhReply
                    dispatchEvent(SshClientStateMachine.SshEvent.ReceiveKex.DhReply(dhReply))
                }

                KexType.DH_GEX -> {
                    // First packet is SSH_MSG_KEX_DH_GEX_GROUP
                    val groupStream = ByteBufferKaitaiStream(rawBody)
                    val groupPayload = KexDhGexPayload(groupStream)
                    groupPayload._read()
                    val group = groupPayload.body() as SshMsgKexDhGexGroup

                    val dhGex = kex as DiffieHellmanGroupExchange
                    dhGex.setGroup(
                        BigInteger(1, group.p().body()),
                        BigInteger(1, group.g().body())
                    )
                    clientPublicKey = dhGex.generateClientKeys()

                    val initMsg = SshMsgKexDhGexInit().apply {
                        setE(createMpint(clientPublicKey!!))
                        _check()
                    }
                    writePacket(
                        SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_INIT.id().toInt(),
                        initMsg.toByteArray()
                    )

                    // Second packet is SSH_MSG_KEX_DH_GEX_REPLY
                    val replyPacket = packetIO.readPacket()
                    val replyMsgType = replyPacket.messageType().id().toByte()
                    val replyRawBody = byteArrayOf(replyMsgType) + replyPacket._raw_body()
                    val replyStream = ByteBufferKaitaiStream(replyRawBody)
                    val replyPayload = KexDhGexPayload(replyStream)
                    replyPayload._read()
                    val reply = replyPayload.body() as SshMsgKexDhGexReply
                    dispatchEvent(SshClientStateMachine.SshEvent.ReceiveKex.DhGexReply(reply))
                }
            }

            // New keys - read server's NEWKEYS
            val newKeysPacket = packetIO.readPacket()
            dispatchEvent(SshClientStateMachine.SshEvent.ReceiveNewKeys)

            // Service request (ssh-userauth)
            // Loop until we get SERVICE_ACCEPT (skip IGNORE/DEBUG messages)
            val serviceAccept = readExpectedMessage<SshMsgServiceAccept>(
                SshEnums.MessageType.SSH_MSG_SERVICE_ACCEPT
            )
            dispatchEvent(
                SshClientStateMachine.SshEvent.ReceiveServiceAccept(serviceAccept.serviceName().value())
            )

            logger.info("SSH connection established successfully")
            startPacketLoop()
            return true
        } catch (e: Exception) {
            logger.error("SSH connection failed", e)
            return false
        }
    }

    /**
     * Authenticate using password.
     *
     * @param username Username
     * @param password Password
     * @return true if authentication succeeded
     */
    suspend fun authenticatePassword(username: String, password: String): Boolean {
        try {
            val req = SshMsgUserauthRequest().apply {
                setUserName(createAsciiString(username))
                setServiceName(createAsciiString("ssh-connection"))
                setMethodName(createAsciiString("password"))

                val passAuth = UserauthRequestPassword().apply {
                    setChangePassword(0)
                    setPlaintextPassword(createUtf8String(password))
                    _check()
                }

                setMethodSpecificFields(passAuth)
                _check()
            }

            val deferred = CompletableDeferred<Boolean>()
            pendingAuth.set(deferred)

            writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray()
            )

            try {
                return deferred.await()
            } finally {
                pendingAuth.clearIfSame(deferred)
            }
        } catch (e: Exception) {
            logger.error("Authentication error", e)
            return false
        }
    }

    /**
     * Authenticate using keyboard-interactive (RFC 4256).
     *
     * @param username Username
     * @param callback Callback that receives prompts and provides responses
     * @return true if authentication succeeded
     */
    suspend fun authenticateKeyboardInteractive(
        username: String,
        callback: KeyboardInteractiveCallback,
    ): Boolean {
        try {
            val req = SshMsgUserauthRequest().apply {
                setUserName(createAsciiString(username))
                setServiceName(createAsciiString("ssh-connection"))
                setMethodName(createAsciiString("keyboard-interactive"))

                val kbdInteractive = UserauthRequestKeyboardInteractive().apply {
                    setLanguageTag(createByteString(ByteArray(0)))
                    setSubmethods(createByteString(ByteArray(0)))
                    _check()
                }
                setMethodSpecificFields(kbdInteractive)
                _check()
            }

            val deferred = CompletableDeferred<Boolean>()
            val channel = Channel<SshMsgUserauthInfoRequest>(Channel.UNLIMITED)
            pendingAuth.set(deferred)
            withContext(stateMachineDispatcher) {
                infoRequestChannel = channel
            }

            writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray()
            )

            val consumerJob = connectionScope.launch {
                for (infoRequest in channel) {
                    val name = String(infoRequest.name().data(), Charsets.UTF_8)
                    val instruction = String(infoRequest.instruction().data(), Charsets.UTF_8)
                    val prompts = infoRequest.prompts().map { prompt ->
                        KeyboardInteractiveCallback.Prompt(
                            text = String(prompt.prompt().data(), Charsets.UTF_8),
                            echo = prompt.echo() != 0
                        )
                    }

                    callback.onInfoRequest(name, instruction, prompts) { responses ->
                        val responseMsg = SshMsgUserauthInfoResponse().apply {
                            setNumResponses(responses.size.toLong())
                            setResponses(
                                responses.map { response ->
                                    val bytes = response.toByteArray(Charsets.UTF_8)
                                    createByteString(bytes)
                                }
                            )
                            _check()
                        }

                        writePacket(
                            SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_61.id().toInt(),
                            responseMsg.toByteArray()
                        )
                    }
                }
            }

            try {
                return deferred.await()
            } finally {
                channel.close()
                consumerJob.cancel()
                pendingAuth.clearIfSame(deferred)
                withContext(stateMachineDispatcher) {
                    if (infoRequestChannel === channel) {
                        infoRequestChannel = null
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Keyboard-interactive authentication error", e)
            return false
        }
    }

    /**
     * Authenticate using public key (RFC 4252 §7).
     *
     * @param username Username
     * @param privateKey Parsed private key
     * @return true if authentication succeeded
     */
    internal suspend fun authenticatePublicKey(username: String, privateKey: SshPrivateKey): Boolean {
        try {
            val sid = sessionId ?: throw SshException("Session ID not established")

            val publicKeyBlob = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)

            val sigAlgorithmName = privateKey.signatureAlgorithm
            val sigEntry = SignatureEntry.fromSshName(sigAlgorithmName)
                ?: throw SshException("Unknown signature algorithm: $sigAlgorithmName")

            // Build the data to sign per RFC 4252 §7
            val signatureData = buildSignatureData(
                sid,
                username,
                "ssh-connection",
                sigAlgorithmName,
                publicKeyBlob
            )

            // Sign the data
            val signature = sigEntry.algorithm.sign(
                sigAlgorithmName,
                privateKey.jcaKeyPair.private,
                signatureData
            )

            // Build the SSH_MSG_USERAUTH_REQUEST
            val req = SshMsgUserauthRequest().apply {
                setUserName(createAsciiString(username))
                setServiceName(createAsciiString("ssh-connection"))
                setMethodName(createAsciiString("publickey"))

                val pubkeyAuth = UserauthRequestPublickey().apply {
                    setHasSignature(1)
                    setPublicKeyAlgorithmName(createAsciiString(sigAlgorithmName))
                    setPublicKeyBlob(createByteString(publicKeyBlob))
                    setSignature(createByteString(signature))
                    _check()
                }

                setMethodSpecificFields(pubkeyAuth)
                _check()
            }

            val deferred = CompletableDeferred<Boolean>()
            pendingAuth.set(deferred)

            writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray()
            )

            try {
                return deferred.await()
            } finally {
                pendingAuth.clearIfSame(deferred)
            }
        } catch (e: Exception) {
            logger.error("Public key authentication error", e)
            return false
        }
    }

    private fun buildSignatureData(
        sessionId: ByteArray,
        username: String,
        serviceName: String,
        algorithmName: String,
        publicKeyBlob: ByteArray,
    ): ByteArray {
        val data = UserauthPublickeySignatureData().apply {
            setSessionIdentifier(createByteString(sessionId))
            setMessageType(byteArrayOf(50))
            setUserName(createByteString(username.toByteArray(Charsets.UTF_8)))
            setServiceName(createByteString(serviceName.toByteArray(Charsets.US_ASCII)))
            setMethodName(createByteString("publickey".toByteArray(Charsets.US_ASCII)))
            setHasSignature(byteArrayOf(1))
            setPublicKeyAlgorithmName(createByteString(algorithmName.toByteArray(Charsets.US_ASCII)))
            setPublicKeyBlob(createByteString(publicKeyBlob))
            _check()
        }
        return data.toByteArray()
    }

    /**
     * Authenticate using the strategy-based [AuthHandler] flow.
     *
     * Drives the authentication per RFC 4252: none → publickey probe → sign →
     * keyboard-interactive → password.
     */
    internal suspend fun authenticate(username: String, handler: AuthHandler): Boolean {
        val channel = Channel<AuthResult>(Channel.UNLIMITED)
        withContext(stateMachineDispatcher) {
            authResultChannel = channel
        }
        try {
            return doAuthenticate(username, handler, channel)
        } finally {
            withContext(stateMachineDispatcher) {
                authResultChannel = null
                currentAuthMethod = null
            }
            channel.close()
        }
    }

    private suspend fun doAuthenticate(
        username: String,
        handler: AuthHandler,
        channel: Channel<AuthResult>,
    ): Boolean {
        if (allowedAuthentications == null) {
            // Step 1: Send "none" auth to discover allowed methods
            sendAuthRequest(username, "none") {
                val noneAuth = UserauthRequestNone().apply { _check() }
                setMethodSpecificFields(noneAuth)
            }

            val noneResult = channel.receive()
            if (noneResult is AuthResult.Success) return true
            if (noneResult !is AuthResult.Failure) return false

            allowedAuthentications = noneResult.allowedMethods
        }

        val allowedMethods = allowedAuthentications!!
        handler.onAuthMethodsAvailable(allowedMethods)

        // Step 2: Public key phase
        if ("publickey" in allowedMethods) {
            val keys = handler.onPublicKeysNeeded()
            for (key in keys) {
                if (key in triedPublicKeys) continue
                val probeResult = probePublicKey(username, key, channel)
                if (probeResult is AuthResult.Success) return true
                if (probeResult is AuthResult.PkOk) {
                    triedPublicKeys.add(key)
                    val signResult = signPublicKey(username, key, handler, channel)
                    if (signResult) return true
                } else {
                    triedPublicKeys.add(key)
                }
                if (probeResult is AuthResult.Failure) {
                    allowedAuthentications = probeResult.allowedMethods
                }
                // AuthResult.Failure → try next key
            }
        }

        for (method in selectPasswordMethods(allowedMethods, preferPasswordAuth)) {
            when (method) {
                is AuthMethod.KeyboardInteractive -> {
                    val kbdResult = doKeyboardInteractive(username, handler, channel)
                    if (kbdResult) return true
                }

                is AuthMethod.Password -> {
                    val password = handler.onPasswordNeeded() ?: return false
                    val passResult = doPasswordAuth(username, password, channel)
                    if (passResult) return true
                }

                is AuthMethod.PublicKey,
                is AuthMethod.Unknown,
                -> {
                    logger.warn("Skipping unexpected auth method: ${AuthMethod.toSshName(method)}")
                }
            }
        }

        return false
    }

    private suspend fun probePublicKey(
        username: String,
        key: AuthPublicKey,
        channel: Channel<AuthResult>,
    ): AuthResult {
        sendAuthRequest(username, "publickey") {
            val pubkeyAuth = UserauthRequestPublickey().apply {
                setHasSignature(0)
                setPublicKeyAlgorithmName(createAsciiString(key.algorithmName))
                setPublicKeyBlob(createByteString(key.publicKeyBlob))
                _check()
            }
            setMethodSpecificFields(pubkeyAuth)
        }
        return channel.receive()
    }

    private suspend fun signPublicKey(
        username: String,
        key: AuthPublicKey,
        handler: AuthHandler,
        channel: Channel<AuthResult>,
    ): Boolean {
        val sid = sessionId ?: throw SshException("Session ID not established")
        val signatureData = buildSignatureData(
            sid,
            username,
            "ssh-connection",
            key.algorithmName,
            key.publicKeyBlob
        )

        val signature = handler.onSignatureRequest(key, signatureData) ?: return false

        sendAuthRequest(username, "publickey") {
            val pubkeyAuth = UserauthRequestPublickey().apply {
                setHasSignature(1)
                setPublicKeyAlgorithmName(createAsciiString(key.algorithmName))
                setPublicKeyBlob(createByteString(key.publicKeyBlob))
                setSignature(createByteString(signature))
                _check()
            }
            setMethodSpecificFields(pubkeyAuth)
        }

        return when (channel.receive()) {
            is AuthResult.Success -> true
            else -> false
        }
    }

    private suspend fun doKeyboardInteractive(
        username: String,
        handler: AuthHandler,
        channel: Channel<AuthResult>,
    ): Boolean {
        sendAuthRequest(username, "keyboard-interactive") {
            val kbdInteractive = UserauthRequestKeyboardInteractive().apply {
                setLanguageTag(createByteString(ByteArray(0)))
                setSubmethods(createByteString(ByteArray(0)))
                _check()
            }
            setMethodSpecificFields(kbdInteractive)
        }

        while (true) {
            when (val result = channel.receive()) {
                is AuthResult.Success -> return true

                is AuthResult.Failure -> {
                    allowedAuthentications = result.allowedMethods
                    return false
                }

                is AuthResult.InfoRequest -> {
                    val responses = handler.onKeyboardInteractivePrompt(
                        result.name,
                        result.instruction,
                        result.prompts
                    ) ?: return false

                    val responseMsg = SshMsgUserauthInfoResponse().apply {
                        setNumResponses(responses.size.toLong())
                        setResponses(
                            responses.map { response ->
                                createByteString(response.toByteArray(Charsets.UTF_8))
                            }
                        )
                        _check()
                    }

                    writePacket(
                        SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_61.id().toInt(),
                        responseMsg.toByteArray()
                    )
                }

                is AuthResult.PkOk -> {
                    // Unexpected during keyboard-interactive
                    return false
                }
            }
        }
    }

    private suspend fun doPasswordAuth(
        username: String,
        password: String,
        channel: Channel<AuthResult>,
    ): Boolean {
        sendAuthRequest(username, "password") {
            val passAuth = UserauthRequestPassword().apply {
                setChangePassword(0)
                setPlaintextPassword(createUtf8String(password))
                _check()
            }
            setMethodSpecificFields(passAuth)
        }

        return when (val result = channel.receive()) {
            is AuthResult.Success -> true

            is AuthResult.Failure -> {
                allowedAuthentications = result.allowedMethods
                false
            }

            else -> false
        }
    }

    private suspend fun sendAuthRequest(
        username: String,
        method: String,
        configure: SshMsgUserauthRequest.() -> Unit,
    ) {
        val req = SshMsgUserauthRequest().apply {
            setUserName(createAsciiString(username))
            setServiceName(createAsciiString("ssh-connection"))
            setMethodName(createAsciiString(method))
            configure()
            _check()
        }
        withContext(stateMachineDispatcher) {
            currentAuthMethod = AuthMethod.fromString(method)
            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray()
            )
        }
    }

    // SshClientCallbacks implementation

    private fun sendVersion() {
        logger.debug("Sending version: $clientVersion")
    }

    private fun receiveVersion(banner: IdBanner) {
        // protoVersion() includes everything after "SSH-" up to and including \r\n
        // For exchange hash, we need "SSH-" + version without the CR-LF
        val versionWithCrlf = banner.protoVersion()
        val versionClean = versionWithCrlf.trimEnd('\r', '\n')
        serverVersion = "SSH-$versionClean"
        logger.info("Server version: $serverVersion")
    }

    private suspend fun sendKexInit() {
        logger.debug("Sending KEX_INIT")

        val kexInit = SshMsgKexinit().apply {
            // Cookie (16 random bytes)
            val cookie = ByteArray(16).apply {
                SecureRandom().nextBytes(this)
            }
            setCookie(cookie)

            setKexAlgorithms(createNameList(kexAlgorithms))
            setServerHostKeyAlgorithms(createNameList(hostKeyAlgorithms))
            setEncryptionAlgorithmsClientToServer(createNameList(encryptionAlgorithms))
            setEncryptionAlgorithmsServerToClient(createNameList(encryptionAlgorithms))
            setMacAlgorithmsClientToServer(createNameList(macAlgorithms))
            setMacAlgorithmsServerToClient(createNameList(macAlgorithms))
            setCompressionAlgorithmsClientToServer(createNameList(compressionAlgorithms))
            setCompressionAlgorithmsServerToClient(createNameList(compressionAlgorithms))
            setLanguagesClientToServer(createNameList(""))
            setLanguagesServerToClient(createNameList(""))
            setFirstKexPacketFollows(0)
            setReserved(0)
            _check()
        }

        val kexInitPayload = kexInit.toByteArray()

        clientKexInit = byteArrayOf(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toByte()) + kexInitPayload

        writePacket(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toInt(), kexInitPayload)
    }

    private fun receiveKexInit(msg: SshMsgKexinit) {
        logger.info("Received KEX_INIT from server")

        val serverKexAlgs = msg.kexAlgorithms().entries().data()
        val serverHostKeyAlgs = msg.serverHostKeyAlgorithms().entries().data()
        val serverEncC2S = msg.encryptionAlgorithmsClientToServer().entries().data()
        val serverEncS2C = msg.encryptionAlgorithmsServerToClient().entries().data()
        val serverMacC2S = msg.macAlgorithmsClientToServer().entries().data()
        val serverMacS2C = msg.macAlgorithmsServerToClient().entries().data()
        val serverCompC2S = msg.compressionAlgorithmsClientToServer().entries().data()
        val serverCompS2C = msg.compressionAlgorithmsServerToClient().entries().data()

        logger.debug("  Server KEX algorithms: $serverKexAlgs")
        logger.debug("  Server host key algorithms: $serverHostKeyAlgs")
        logger.debug("  Server encryption c->s: $serverEncC2S")
        logger.debug("  Server encryption s->c: $serverEncS2C")
        logger.debug("  Server MAC c->s: $serverMacC2S")
        logger.debug("  Server MAC s->c: $serverMacS2C")
        logger.debug("  Server compression c->s: $serverCompC2S")
        logger.debug("  Server compression s->c: $serverCompS2C")

        val clientKexStrict = kexAlgorithms.contains("kex-strict-c-v00@openssh.com")
        val serverKexStrict = serverKexAlgs.contains("kex-strict-s-v00@openssh.com")
        strictKexEnabled = clientKexStrict && serverKexStrict
        if (strictKexEnabled) {
            logger.info("  Strict KEX enabled")
        }

        val clientKexList = kexAlgorithms.split(",")
        negotiatedKex = clientKexList.firstOrNull { it in serverKexAlgs }
            ?: throw SshException("No matching KEX algorithm. Client: $kexAlgorithms, Server: $serverKexAlgs")
        logger.info("  Negotiated KEX: $negotiatedKex")

        val clientHostKeyList = hostKeyAlgorithms.split(",")
        val matchingHostKey = clientHostKeyList.firstOrNull { it in serverHostKeyAlgs }
            ?: throw SshException("No matching host key algorithm. Client: $hostKeyAlgorithms, Server: $serverHostKeyAlgs")
        logger.info("  Negotiated host key: $matchingHostKey")

        val clientEncList = encryptionAlgorithms.split(",")
        negotiatedEncryptionC2S = clientEncList.firstOrNull { it in serverEncC2S }
            ?: throw SshException("No matching encryption algorithm (c->s). Client: $encryptionAlgorithms, Server: $serverEncC2S")
        negotiatedEncryptionS2C = clientEncList.firstOrNull { it in serverEncS2C }
            ?: throw SshException("No matching encryption algorithm (s->c). Client: $encryptionAlgorithms, Server: $serverEncS2C")
        logger.info("  Negotiated encryption c->s: $negotiatedEncryptionC2S")
        logger.info("  Negotiated encryption s->c: $negotiatedEncryptionS2C")

        val isAeadC2S = CipherEntry.fromSshName(negotiatedEncryptionC2S!!)?.isAead == true
        val isAeadS2C = CipherEntry.fromSshName(negotiatedEncryptionS2C!!)?.isAead == true

        if (!isAeadC2S) {
            val clientMacList = macAlgorithms.split(",")
            negotiatedMacC2S = clientMacList.firstOrNull { it in serverMacC2S }
                ?: throw SshException("No matching MAC algorithm (c->s). Client: $macAlgorithms, Server: $serverMacC2S")
            logger.info("  Negotiated MAC c->s: $negotiatedMacC2S")
        } else {
            logger.info("  MAC c->s: not needed (AEAD)")
        }

        if (!isAeadS2C) {
            val clientMacList = macAlgorithms.split(",")
            negotiatedMacS2C = clientMacList.firstOrNull { it in serverMacS2C }
                ?: throw SshException("No matching MAC algorithm (s->c). Client: $macAlgorithms, Server: $serverMacS2C")
            logger.info("  Negotiated MAC s->c: $negotiatedMacS2C")
        } else {
            logger.info("  MAC s->c: not needed (AEAD)")
        }

        val clientCompList = compressionAlgorithms.split(",")
        negotiatedCompressionC2S = clientCompList.firstOrNull { it in serverCompC2S }
            ?: throw SshException("No matching compression algorithm (c->s). Client: $compressionAlgorithms, Server: $serverCompC2S")
        negotiatedCompressionS2C = clientCompList.firstOrNull { it in serverCompS2C }
            ?: throw SshException("No matching compression algorithm (s->c). Client: $compressionAlgorithms, Server: $serverCompS2C")
        logger.info("  Negotiated compression c->s: $negotiatedCompressionC2S")
        logger.info("  Negotiated compression s->c: $negotiatedCompressionS2C")
    }

    private suspend fun sendKexExchangeInit() {
        val kexName = negotiatedKex ?: throw SshException("No KEX algorithm negotiated")
        val kexEntry = KexEntry.fromSshName(kexName)
            ?: throw SshException("Unknown KEX algorithm: $kexName")
        when (kexEntry.type) {
            KexType.ECDH -> sendKexEcdhInit(kexEntry)
            KexType.DH -> sendKexDhInit(kexEntry)
            KexType.DH_GEX -> sendKexDhGexRequest(kexEntry)
        }
    }

    private suspend fun sendKexDhInit(kexEntry: KexEntry) {
        logger.debug("Sending DH_INIT")

        val dh = kexEntry.create()
        kex = dh
        clientPublicKey = dh.generateClientKeys()

        val pubKey = clientPublicKey
            ?: throw SshException("Client public key not generated")

        val msg = SshMsgKexdhInit().apply {
            setE(createMpint(pubKey))
            _check()
        }

        writePacket(SshEnums.KexDh.SSH_MSG_KEXDH_INIT.id().toInt(), msg.toByteArray())
    }

    private suspend fun sendKexEcdhInit(kexEntry: KexEntry) {
        logger.debug("Sending ECDH_INIT (${kexEntry.sshName})")

        val ecdh = kexEntry.create()
        kex = ecdh
        clientPublicKey = ecdh.generateClientKeys()

        val pubKey = clientPublicKey
            ?: throw SshException("Client public key not generated")

        val msg = SshMsgKexEcdhInit().apply {
            setQC(createByteString(pubKey))
            _check()
        }

        writePacket(SshEnums.KexEcdh.SSH_MSG_KEX_ECDH_INIT.id().toInt(), msg.toByteArray())
    }

    private suspend fun sendKexDhGexRequest(kexEntry: KexEntry) {
        logger.debug("Sending DH_GEX_REQUEST (${kexEntry.sshName})")

        val dhGex = kexEntry.create() as DiffieHellmanGroupExchange
        kex = dhGex

        val msg = SshMsgKexDhGexRequest().apply {
            setMin(dhGex.min.toLong())
            setN(dhGex.n.toLong())
            setMax(dhGex.max.toLong())
            _check()
        }

        writePacket(SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_REQUEST.id().toInt(), msg.toByteArray())
    }

    private suspend fun receiveKexDhReply(msg: SshMsgKexdhReply) {
        logger.info("Received DH_REPLY from server")
        completeKex(
            serverHostKey = msg.serverKey().data(),
            serverPublicKey = msg.f().body(),
            signature = msg.signatureH().data()
        )
    }

    private suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) {
        logger.info("Received ECDH_REPLY from server")
        completeKex(
            serverHostKey = msg.kS().data(),
            serverPublicKey = msg.qS().data(),
            signature = msg.signatureH().data()
        )
    }

    private suspend fun completeKex(serverHostKey: ByteArray, serverPublicKey: ByteArray, signature: ByteArray) {
        val kexAlg = kex ?: throw SshException("No KEX algorithm initialized")
        val sv = serverVersion ?: throw SshException("Server version not received")
        val cki = clientKexInit ?: throw SshException("Client KEX_INIT not sent")
        val ski = serverKexInit ?: throw SshException("Server KEX_INIT not received")
        val cpk = clientPublicKey ?: throw SshException("Client public key not generated")

        sharedSecret = kexAlg.computeSharedSecret(serverPublicKey)

        val secret = sharedSecret
            ?: throw SshException("Shared secret computation failed")

        exchangeHash = kexAlg.computeExchangeHash(
            clientVersion.toByteArray(),
            sv.toByteArray(),
            cki,
            ski,
            serverHostKey,
            cpk,
            serverPublicKey,
            secret
        )

        val hash = exchangeHash
            ?: throw SshException("Exchange hash computation failed")

        if (sessionId == null) {
            sessionId = hash
        }

        val keyType = try {
            val stream = ByteBufferKaitaiStream(serverHostKey)
            val str = AsciiString(stream)
            str._read()
            str.value()
        } catch (e: Exception) {
            logger.error("Failed to parse server host key type", e)
            throw SshException("Invalid host key format")
        }

        val publicKey = PublicKey(keyType, serverHostKey)

        serverHostKeyBlob = serverHostKey

        val trusted = hostKeyVerifier.verify(publicKey)

        if (!trusted) {
            logger.error("Host key verification failed")
            throw SshException("Host key verification failed")
        }
        logger.info("Host key verified")

        if (!SignatureVerifier.verify(serverHostKey, signature, hash)) {
            logger.error("Server signature verification failed")
            throw SshException("Server signature verification failed")
        }
        logger.info("Server signature verified")
    }

    private suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) {
        logger.info("Received DH_GEX_REPLY from server")
        completeKex(
            serverHostKey = msg.serverPublicHostKey().data(),
            serverPublicKey = msg.f().body(),
            signature = msg.signatureH().data()
        )
    }

    private suspend fun sendNewKeys() {
        logger.debug("Sending NEW_KEYS")
        writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt())
        if (strictKexEnabled) {
            packetIO.resetSendSequenceNumber()
        }
    }

    private fun receiveNewKeys() {
        logger.info("Received NEW_KEYS from server")
        if (strictKexEnabled) {
            packetIO.resetReceiveSequenceNumber()
        }
    }

    private fun activateEncryption() {
        logger.info("Activating encryption")

        val encC2S = negotiatedEncryptionC2S
            ?: throw SshException("No encryption algorithm negotiated for client-to-server")
        val encS2C = negotiatedEncryptionS2C
            ?: throw SshException("No encryption algorithm negotiated for server-to-client")

        val cipherC2S = CipherEntry.fromSshName(encC2S)
            ?: throw SshException("Unknown cipher: $encC2S")

        if (cipherC2S.isAead) {
            activateAeadEncryption(encC2S, encS2C)
        } else {
            activateNonAeadEncryption(encC2S, encS2C)
        }

        logger.info("Encryption active")

        val compC2SName = negotiatedCompressionC2S
        val compS2CName = negotiatedCompressionS2C
        if (compC2SName != null && compS2CName != null) {
            val compC2S = CompressionEntry.fromSshName(compC2SName)
            val compS2C = CompressionEntry.fromSshName(compS2CName)
            if (compC2S != null && compS2C != null) {
                val immediateActivation = !compC2S.delayedActivation && !compS2C.delayedActivation
                packetIO.enableCompression(compC2S.create(), compS2C.create(), immediateActivation)
                logger.info("Compression configured: c2s=$compC2SName, s2c=$compS2CName, immediate=$immediateActivation")
            }
        }
    }

    private fun activateAeadEncryption(encC2S: String, encS2C: String) {
        val entryC2S = CipherEntry.fromSshName(encC2S)
            ?: throw SshException("Unknown AEAD cipher: $encC2S")
        val entryS2C = CipherEntry.fromSshName(encS2C)
            ?: throw SshException("Unknown AEAD cipher: $encS2C")

        val keyLength = maxOf(entryC2S.keyLength, entryS2C.keyLength)
        val ivLength = maxOf(entryC2S.ivLength, entryS2C.ivLength)

        val secret = sharedSecret ?: throw SshException("Shared secret not computed")
        val hash = exchangeHash ?: throw SshException("Exchange hash not computed")
        val sid = sessionId ?: throw SshException("Session ID not established")
        val kexAlg = kex ?: throw SshException("No KEX algorithm initialized")

        val keyDerivation = KeyDerivation(
            secret,
            hash,
            sid,
            kexAlg.hashAlgorithm
        )

        val keys = keyDerivation.deriveKeys(
            ivLength = ivLength,
            keyLength = keyLength,
            macKeyLength = 0
        )

        val c2sKey = keys.encryptionKeyClientToServer.copyOf(entryC2S.keyLength)
        val s2cKey = keys.encryptionKeyServerToClient.copyOf(entryS2C.keyLength)
        val c2sIv = if (entryC2S.ivLength > 0) keys.initialIvClientToServer.copyOf(entryC2S.ivLength) else ByteArray(0)
        val s2cIv = if (entryS2C.ivLength > 0) keys.initialIvServerToClient.copyOf(entryS2C.ivLength) else ByteArray(0)

        val c2sAead = (entryC2S.create(c2sKey, c2sIv, true) as EncryptionInstance.Aead).aead
        val s2cAead = (entryS2C.create(s2cKey, s2cIv, false) as EncryptionInstance.Aead).aead

        packetIO.enableAead(c2sAead, s2cAead)
    }

    private fun activateNonAeadEncryption(encC2S: String, encS2C: String) {
        val cipherEntryC2S = CipherEntry.fromSshName(encC2S)
            ?: throw SshException("Unknown cipher: $encC2S")
        val cipherEntryS2C = CipherEntry.fromSshName(encS2C)
            ?: throw SshException("Unknown cipher: $encS2C")

        val macC2SName = negotiatedMacC2S
            ?: throw SshException("No MAC algorithm negotiated for client-to-server")
        val macS2CName = negotiatedMacS2C
            ?: throw SshException("No MAC algorithm negotiated for server-to-client")

        val macEntryC2S = MacEntry.fromSshName(macC2SName)
            ?: throw SshException("Unknown MAC algorithm: $macC2SName")
        val macEntryS2C = MacEntry.fromSshName(macS2CName)
            ?: throw SshException("Unknown MAC algorithm: $macS2CName")

        val keyLength = maxOf(cipherEntryC2S.keyLength, cipherEntryS2C.keyLength)
        val ivLength = maxOf(cipherEntryC2S.ivLength, cipherEntryS2C.ivLength)
        val macKeyLength = maxOf(macEntryC2S.keyLength, macEntryS2C.keyLength)

        val secret = sharedSecret ?: throw SshException("Shared secret not computed")
        val hash = exchangeHash ?: throw SshException("Exchange hash not computed")
        val sid = sessionId ?: throw SshException("Session ID not established")
        val kexAlg = kex ?: throw SshException("No KEX algorithm initialized")

        val keyDerivation = KeyDerivation(
            secret,
            hash,
            sid,
            kexAlg.hashAlgorithm
        )

        val keys = keyDerivation.deriveKeys(
            ivLength = ivLength,
            keyLength = keyLength,
            macKeyLength = macKeyLength
        )

        val c2sCipherKey = keys.encryptionKeyClientToServer.copyOf(cipherEntryC2S.keyLength)
        val s2cCipherKey = keys.encryptionKeyServerToClient.copyOf(cipherEntryS2C.keyLength)

        val c2sIv = keys.initialIvClientToServer.copyOf(cipherEntryC2S.ivLength)
        val s2cIv = keys.initialIvServerToClient.copyOf(cipherEntryS2C.ivLength)

        val clientToServerCipher = (cipherEntryC2S.create(c2sCipherKey, c2sIv, true) as EncryptionInstance.Cipher).cipher
        val serverToClientCipher = (cipherEntryS2C.create(s2cCipherKey, s2cIv, false) as EncryptionInstance.Cipher).cipher

        val clientToServerMac = macEntryC2S.create(keys.integrityKeyClientToServer)
        val serverToClientMac = macEntryS2C.create(keys.integrityKeyServerToClient)

        packetIO.enableEncryption(
            clientToServerCipher,
            clientToServerMac,
            serverToClientCipher,
            serverToClientMac,
            clientToServerEtm = macEntryC2S.isEtm,
            serverToClientEtm = macEntryS2C.isEtm
        )
    }

    private suspend fun sendServiceRequest(service: String) {
        logger.info("Requesting service: $service")

        val msg = SshMsgServiceRequest().apply {
            setServiceName(createAsciiString(service))
            _check()
        }

        writePacket(SshEnums.MessageType.SSH_MSG_SERVICE_REQUEST.id().toInt(), msg.toByteArray())
    }

    private fun receiveServiceAccept(service: String) {
        logger.info("Service accepted: $service")
    }

    private fun startAuthentication() {
        logger.info("Starting authentication")
    }

    private fun authenticationSuccess() {
        logger.info("Authentication successful")
        packetIO.activateCompression()
        pendingAuth.complete(true)
    }

    private fun authenticationFailure() {
        logger.warn("Authentication failed")
        pendingAuth.complete(false)
    }

    private fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest) {
        val channel = infoRequestChannel
        if (channel != null) {
            val sent = channel.trySend(msg)
            if (sent.isFailure) {
                logger.warn("Failed to deliver info request to consumer")
            }
        } else {
            logger.warn("Received info request but no consumer is registered")
        }
    }

    private fun receiveUserauthBanner(msg: SshMsgUserauthBanner) {
        logger.info("SSH banner: ${msg.message().value()}")
    }

    private fun debug(msg: SshMsgDebug) {
        logger.debug("SSH debug: ${msg.message()}")
    }

    private fun ignore() {
        logger.trace("Received IGNORE message")
    }

    private suspend fun disconnect() {
        logger.info("Disconnecting (received SSH_MSG_DISCONNECT from server)")
        _disconnectedFlow.tryEmit(null)
        transport.close()
    }

    /**
     * Enable SSH agent forwarding with the provided agent.
     *
     * Must be called before the remote server opens agent channels.
     * When agent forwarding is enabled, remote servers can request
     * signatures from your agent provider.
     *
     * @param provider Agent implementation that handles signing requests
     */
    fun enableAgentForwarding(provider: AgentProvider) {
        this.agentProvider = provider
        logger.info("Agent forwarding enabled")
    }

    private suspend fun handleIncomingChannelOpen(packet: UnencryptedPacket.UnencryptedPayload) {
        try {
            val rawBody = packet._raw_body()
            val stream = ByteBufferKaitaiStream(rawBody)
            val msg = SshMsgChannelOpen(stream)
            msg._read()

            val channelType = msg.channelType().value()
            val senderChannel = msg.senderChannel().toInt()
            val initialWindow = msg.initialWindowSize()
            val maxPacketSize = msg.maximumPacketSize().toInt()

            logger.info("Received CHANNEL_OPEN: type=$channelType, sender=$senderChannel")

            when (channelType) {
                "auth-agent@openssh.com" -> {
                    if (agentProvider == null) {
                        rejectChannelOpen(senderChannel, channelType)
                        return
                    }
                    val localChannelNumber = allocateChannelNumber()

                    val sessionInfo = AgentSessionInfo(
                        sessionId = sessionId ?: ByteArray(0),
                        serverHostKey = serverHostKeyBlob ?: ByteArray(0)
                    )
                    val handler = AgentProtocolHandler(agentProvider!!, sessionInfo)
                    val agentChannel = AgentChannel(
                        handler,
                        this,
                        localChannelNumber,
                        senderChannel,
                        maxPacketSize,
                        initialWindow
                    )

                    agentChannels[localChannelNumber] = agentChannel
                    agentChannelsByRemote[localChannelNumber] = agentChannel

                    sendChannelOpenConfirmation(
                        recipientChannel = senderChannel,
                        senderChannel = localChannelNumber,
                        initialWindowSize = 64 * 1024,
                        maximumPacketSize = 32 * 1024
                    )
                    logger.info("Accepted agent channel: local=$localChannelNumber, remote=$senderChannel")
                }

                "forwarded-tcpip" -> {
                    handleForwardedTcpip(msg, senderChannel, initialWindow, maxPacketSize)
                }

                else -> {
                    rejectChannelOpen(senderChannel, channelType)
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to handle incoming channel open", e)
        }
    }

    private suspend fun handleForwardedTcpip(
        msg: SshMsgChannelOpen,
        senderChannel: Int,
        initialWindow: Long,
        maxPacketSize: Int,
    ) {
        try {
            val channelData = msg.channelSpecificData()
            if (channelData !is ChannelOpenForwardedTcpip) {
                logger.warn("Failed to parse forwarded-tcpip channel data")
                rejectChannelOpen(senderChannel, "forwarded-tcpip")
                return
            }

            val connectedAddr = String(channelData.connectedAddress().data(), Charsets.US_ASCII)
            val connectedPort = channelData.connectedPort().toInt()
            val originAddr = String(channelData.originatorAddress().data(), Charsets.US_ASCII)
            val originPort = channelData.originatorPort().toInt()

            val key = "$connectedAddr:$connectedPort"
            val handler = remoteForwarders[key]
            if (handler == null) {
                logger.warn("No remote forwarder registered for $key")
                rejectChannelOpen(senderChannel, "forwarded-tcpip")
                return
            }

            handler(connectedAddr, connectedPort, originAddr, originPort, senderChannel, initialWindow, maxPacketSize)
        } catch (e: Exception) {
            logger.error("Failed to handle forwarded-tcpip", e)
            rejectChannelOpen(senderChannel, "forwarded-tcpip")
        }
    }

    private suspend fun rejectChannelOpen(senderChannel: Int, channelType: String) {
        logger.warn("Rejecting channel open: type=$channelType")
        sendChannelOpenFailure(
            recipientChannel = senderChannel,
            reasonCode = 3,
            description = "Channel type not supported",
            languageTag = ""
        )
    }

    private suspend fun sendChannelOpenConfirmation(
        recipientChannel: Int,
        senderChannel: Int,
        initialWindowSize: Int,
        maximumPacketSize: Int,
    ) {
        val msg = SshMsgChannelOpenConfirmation()
        msg.setRecipientChannel(recipientChannel.toLong())
        msg.setSenderChannel(senderChannel.toLong())
        msg.setInitialWindowSize(initialWindowSize.toLong())
        msg.setMaximumPacketSize(maximumPacketSize.toLong())
        msg._check()

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.id().toInt(),
            msg.toByteArray()
        )
    }

    private suspend fun sendChannelOpenFailure(
        recipientChannel: Int,
        reasonCode: Int,
        description: String,
        languageTag: String,
    ) {
        val msg = SshMsgChannelOpenFailure()
        msg.setRecipientChannel(recipientChannel.toLong())
        msg.setReasonCode(reasonCode.toLong())
        msg.setDescription(createByteString(description.toByteArray(Charsets.UTF_8)))
        msg.setLanguageTag(createByteString(languageTag.toByteArray(Charsets.UTF_8)))
        msg._check()

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE.id().toInt(),
            msg.toByteArray()
        )
    }

    suspend fun close() {
        connectionScope.cancel()
        transport.close()
        packetLoopJob?.join()
        packetLoopJob = null
        stateMachineDispatcher.close()
    }

    private fun onStateEnter(stateName: String) {
        logger.debug("State: $stateName")
    }

    private fun onStateExit(stateName: String) {
        // Not logging state exits to reduce verbosity
    }

    private suspend fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int) {
        logger.debug("Sending CHANNEL_OPEN: $channelType (local=$localChannelNumber)")

        val msg = SshMsgChannelOpen().apply {
            setChannelType(createAsciiString(channelType))
            setSenderChannel(localChannelNumber.toLong())
            setInitialWindowSize(initialWindowSize.toLong())
            setMaximumPacketSize(maxPacketSize.toLong())

            val sessionData = ChannelOpenSession().apply {
                _check()
            }
            setChannelSpecificData(sessionData)
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN.id().toInt(),
            msg.toByteArray()
        )
    }

    private fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) {
        logger.info("Channel open confirmed")
        pendingChannelOpen.complete(msg)
    }

    private fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) {
        logger.error("Channel open failed: ${msg.reasonCode()}")
        pendingChannelOpen.complete(null)
    }

    private suspend fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) {
        logger.debug("Sending CHANNEL_REQUEST: $requestType (channel=$recipientChannel, wantReply=$wantReply)")
        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST.id().toInt(),
            message.toByteArray()
        )
    }

    private fun receiveChannelSuccess() {
        logger.debug("Channel request succeeded")
        pendingChannelRequest.complete(true)
    }

    private fun receiveChannelFailure() {
        logger.warn("Channel request failed")
        pendingChannelRequest.complete(false)
    }

    private suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest) {
        val requestName = msg.requestName().value()
        val wantReply = msg.wantReply() != 0

        logger.debug("Received global request: $requestName (want_reply=$wantReply)")

        if (wantReply) {
            logger.debug("Sending REQUEST_FAILURE for unhandled global request: $requestName")
            writePacket(SshEnums.MessageType.SSH_MSG_REQUEST_FAILURE.id().toInt())
        }
    }

    // Port forwarding support

    internal suspend fun allocateChannelNumber(): Int {
        channelNumberLock.withLock {
            return nextLocalChannelNumber++
        }
    }

    internal suspend fun openDirectTcpipChannel(
        host: String,
        port: Int,
        originAddr: String,
        originPort: Int,
        initialWindowSize: Int = 256 * 1024,
        maxPacketSize: Int = 32 * 1024,
    ): ForwardingChannel? {
        val localChannelNumber = allocateChannelNumber()

        logger.info("Opening direct-tcpip channel to $host:$port (local=$localChannelNumber)")

        val deferred = CompletableDeferred<ForwardingChannel?>()
        pendingChannelOpens[localChannelNumber] = PendingChannelOpen(deferred, maxPacketSize, initialWindowSize)

        val channelSpecificData = ChannelOpenDirectTcpip().apply {
            setHostToConnect(createByteString(host.toByteArray(Charsets.US_ASCII)))
            setPortToConnect(port.toLong())
            setOriginatorAddress(createByteString(originAddr.toByteArray(Charsets.US_ASCII)))
            setOriginatorPort(originPort.toLong())
            _check()
        }

        val msg = SshMsgChannelOpen().apply {
            setChannelType(createAsciiString("direct-tcpip"))
            setSenderChannel(localChannelNumber.toLong())
            setInitialWindowSize(initialWindowSize.toLong())
            setMaximumPacketSize(maxPacketSize.toLong())
            setChannelSpecificData(channelSpecificData)
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN.id().toInt(),
            msg.toByteArray()
        )

        return try {
            deferred.await()
        } finally {
            pendingChannelOpens.remove(localChannelNumber)
        }
    }

    internal suspend fun sendTcpipForwardRequest(address: String, port: Int): Int? {
        logger.info("Sending tcpip-forward request: $address:$port")

        val requestData = GlobalRequestTcpipForward().apply {
            setAddressToBind(createByteString(address.toByteArray(Charsets.US_ASCII)))
            setPortToBind(port.toLong())
            _check()
        }

        val msg = SshMsgGlobalRequest().apply {
            setRequestName(createAsciiString("tcpip-forward"))
            setWantReply(1)
            setRequestSpecificFields(requestData)
            _check()
        }

        val deferred = CompletableDeferred<ByteArray?>()
        withContext(stateMachineDispatcher) {
            pendingGlobalRequest.setDirect(deferred)
            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST.id().toInt(),
                msg.toByteArray()
            )
        }

        val responseData = try {
            deferred.await()
        } finally {
            pendingGlobalRequest.clearIfSame(deferred)
        } ?: return null

        // If port was 0, the response contains the assigned port
        return if (port == 0 && responseData.isNotEmpty()) {
            val stream = ByteBufferKaitaiStream(responseData)
            val response = GlobalRequestResponseTcpipForward(stream)
            response._read()
            response.boundPort().toInt()
        } else {
            port
        }
    }

    internal suspend fun sendCancelTcpipForward(address: String, port: Int) {
        logger.info("Sending cancel-tcpip-forward: $address:$port")

        val requestData = GlobalRequestCancelTcpipForward().apply {
            setAddressToBind(createByteString(address.toByteArray(Charsets.US_ASCII)))
            setPortToBind(port.toLong())
            _check()
        }

        val msg = SshMsgGlobalRequest().apply {
            setRequestName(createAsciiString("cancel-tcpip-forward"))
            setWantReply(0)
            setRequestSpecificFields(requestData)
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST.id().toInt(),
            msg.toByteArray()
        )
    }

    internal fun registerRemoteForwarder(key: String, handler: suspend (String, Int, String, Int, Int, Long, Int) -> Unit) {
        remoteForwarders[key] = handler
    }

    internal fun unregisterRemoteForwarder(key: String) {
        remoteForwarders.remove(key)
    }

    internal fun registerForwardingChannel(channel: ForwardingChannel) {
        forwardingChannels[channel.localChannelNumber] = channel
        forwardingChannelsByRemote[channel.localChannelNumber] = channel
    }

    internal fun unregisterForwardingChannel(channel: ForwardingChannel) {
        forwardingChannels.remove(channel.localChannelNumber)
        forwardingChannelsByRemote.remove(channel.localChannelNumber)
    }

    internal suspend fun sendChannelOpenConfirmationPublic(
        recipientChannel: Int,
        senderChannel: Int,
        initialWindowSize: Int,
        maximumPacketSize: Int,
    ) {
        sendChannelOpenConfirmation(recipientChannel, senderChannel, initialWindowSize, maximumPacketSize)
    }

    internal suspend fun sendChannelOpenFailurePublic(
        recipientChannel: Int,
        reasonCode: Int,
        description: String,
        languageTag: String,
    ) {
        sendChannelOpenFailure(recipientChannel, reasonCode, description, languageTag)
    }

    // Packet processing

    /**
     * Read and dispatch the next packet through the state machine.
     * This is the central packet processing loop that converts packets to events.
     */
    private suspend fun processNextPacket() {
        val packet = packetIO.readPacket()
        val msgType = packet.messageType()
        logger.debug("Received packet: $msgType")

        withContext(stateMachineDispatcher) {
            when (msgType) {
                SshEnums.MessageType.SSH_MSG_IGNORE -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveIgnore)
                }

                SshEnums.MessageType.SSH_MSG_DEBUG -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveDebug(packet.body() as SshMsgDebug))
                }

                SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST -> {
                    try {
                        val rawBody = packet._raw_body()
                        val stream = ByteBufferKaitaiStream(rawBody)
                        val globalRequestMsg = SshMsgGlobalRequest(stream)
                        globalRequestMsg._read()
                        stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveGlobalRequest(globalRequestMsg))
                    } catch (e: Exception) {
                        logger.error("Failed to parse SSH_MSG_GLOBAL_REQUEST", e)
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN -> {
                    handleIncomingChannelOpen(packet)
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> {
                    val confirmationMsg = parseBody<SshMsgChannelOpenConfirmation>(packet)
                    val recipientChannel = confirmationMsg.recipientChannel().toInt()
                    val pending = pendingChannelOpens.remove(recipientChannel)
                    if (pending != null) {
                        val remoteChannelNumber = confirmationMsg.senderChannel().toInt()
                        val remoteWindow = confirmationMsg.initialWindowSize()
                        logger.info("Direct-tcpip channel opened: local=$recipientChannel, remote=$remoteChannelNumber")
                        val channel = ForwardingChannel(
                            this@SshConnection,
                            recipientChannel,
                            remoteChannelNumber,
                            pending.maxPacketSize,
                            remoteWindowSizeInitial = remoteWindow,
                            initialWindowSize = pending.initialWindowSize
                        )
                        registerForwardingChannel(channel)
                        pending.deferred.complete(channel)
                    } else {
                        stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelOpenConfirmation(confirmationMsg))
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE -> {
                    val failureMsg = parseBody<SshMsgChannelOpenFailure>(packet)
                    val recipientChannel = failureMsg.recipientChannel().toInt()
                    val pending = pendingChannelOpens.remove(recipientChannel)
                    if (pending != null) {
                        pending.deferred.complete(null)
                    } else {
                        stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelOpenFailure(failureMsg))
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_DATA -> {
                    val msg = parseBody<SshMsgChannelData>(packet)
                    val recipientChannel = msg.recipientChannel().toInt()
                    val channel = channelsByRemote[recipientChannel]
                    val agentChannel = agentChannelsByRemote[recipientChannel]
                    val fwdChannel = forwardingChannelsByRemote[recipientChannel]
                    when {
                        channel != null -> channel.onData(msg.data().data())
                        agentChannel != null -> agentChannel.handleData(msg.data().data())
                        fwdChannel != null -> fwdChannel.onData(msg.data().data())
                        else -> logger.warn("Data for unknown channel $recipientChannel")
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA -> {
                    val msg = parseBody<SshMsgChannelExtendedData>(packet)
                    val channel = channelsByRemote[msg.recipientChannel().toInt()]
                    if (channel != null) {
                        channel.onExtendedData(msg.dataTypeCode().toInt(), msg.data().data())
                    } else {
                        logger.warn("Extended data for unknown channel ${msg.recipientChannel()}")
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST -> {
                    val msg = parseBody<SshMsgChannelWindowAdjust>(packet)
                    val recipientChannel = msg.recipientChannel().toInt()
                    val channel = channelsByRemote[recipientChannel]
                    val agentChannel = agentChannelsByRemote[recipientChannel]
                    val fwdChannel = forwardingChannelsByRemote[recipientChannel]
                    when {
                        channel != null -> channel.onWindowAdjust(msg.bytesToAdd())
                        agentChannel != null -> agentChannel.onWindowAdjust(msg.bytesToAdd())
                        fwdChannel != null -> fwdChannel.onWindowAdjust(msg.bytesToAdd())
                        else -> logger.warn("Window adjust for unknown channel $recipientChannel")
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_EOF -> {
                    val msg = parseBody<SshMsgChannelEof>(packet)
                    val recipientChannel = msg.recipientChannel().toInt()
                    val channel = channelsByRemote[recipientChannel]
                    val agentChannel = agentChannelsByRemote[recipientChannel]
                    val fwdChannel = forwardingChannelsByRemote[recipientChannel]
                    when {
                        channel != null -> channel.onEof()
                        agentChannel != null -> agentChannel.onEof()
                        fwdChannel != null -> fwdChannel.onEof()
                        else -> logger.warn("EOF for unknown channel $recipientChannel")
                    }
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE -> {
                    val msg = parseBody<SshMsgChannelClose>(packet)
                    val recipientChannel = msg.recipientChannel().toInt()
                    logger.debug("Received CHANNEL_CLOSE for remote channel $recipientChannel (channels: ${channels.size}, forwardingChannels: ${forwardingChannels.size})")
                    val channel = channelsByRemote[recipientChannel]
                    val agentChannel = agentChannelsByRemote[recipientChannel]
                    val fwdChannel = forwardingChannelsByRemote[recipientChannel]
                    when {
                        channel != null -> channel.onClose()

                        agentChannel != null -> agentChannel.onClose()

                        fwdChannel != null -> {
                            fwdChannel.onClose()
                            unregisterForwardingChannel(fwdChannel)
                        }

                        else -> logger.warn("Close for unknown channel $recipientChannel")
                    }
                    checkAllChannelsClosed()
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST -> {
                    val rawBody = packet._raw_body()
                    val stream = ByteBufferKaitaiStream(rawBody)
                    val msg = SshMsgChannelRequest(stream)
                    msg._read()
                    logger.debug("Received channel request: ${msg.requestType().value()} (want_reply=${msg.wantReply() != 0})")
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_SUCCESS -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelSuccess)
                }

                SshEnums.MessageType.SSH_MSG_CHANNEL_FAILURE -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelFailure)
                }

                SshEnums.MessageType.SSH_MSG_USERAUTH_SUCCESS -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.AuthenticationSuccess)
                    val ch = authResultChannel
                    if (ch != null) {
                        ch.trySend(AuthResult.Success)
                    }
                }

                SshEnums.MessageType.SSH_MSG_USERAUTH_FAILURE -> {
                    val ch = authResultChannel
                    if (ch != null) {
                        val msg = parseBody<SshMsgUserauthFailure>(packet)
                        val methods = msg.validAuthentications().entries().data().toSet()
                        val partial = msg.partialSuccess() != 0
                        ch.trySend(AuthResult.Failure(methods, partial))
                    } else {
                        stateMachine.processEvent(SshClientStateMachine.SshEvent.AuthenticationFailure)
                    }
                }

                SshEnums.MessageType.SSH_MSG_USERAUTH_BANNER -> {
                    val msg = parseBody<SshMsgUserauthBanner>(packet)
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveUserauthBanner(msg))
                }

                SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_60 -> {
                    val ch = authResultChannel
                    if (ch != null && currentAuthMethod is AuthMethod.PublicKey) {
                        val msg = parseBody<SshMsgUserauthPkOk>(packet)
                        ch.trySend(
                            AuthResult.PkOk(
                                msg.publicKeyAlgorithmName().value(),
                                msg.publicKeyBlob().data()
                            )
                        )
                    } else if (ch != null && currentAuthMethod is AuthMethod.KeyboardInteractive) {
                        val msg = parseBody<SshMsgUserauthInfoRequest>(packet)
                        val name = String(msg.name().data(), Charsets.UTF_8)
                        val instruction = String(msg.instruction().data(), Charsets.UTF_8)
                        val prompts = msg.prompts().map { prompt ->
                            KeyboardInteractiveCallback.Prompt(
                                text = String(prompt.prompt().data(), Charsets.UTF_8),
                                echo = prompt.echo() != 0
                            )
                        }
                        ch.trySend(AuthResult.InfoRequest(name, instruction, prompts))
                    } else {
                        val msg = parseBody<SshMsgUserauthInfoRequest>(packet)
                        stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveUserauthInfoRequest(msg))
                    }
                }

                SshEnums.MessageType.SSH_MSG_REQUEST_SUCCESS -> {
                    val rawBody = packet._raw_body()
                    if (!pendingGlobalRequest.complete(rawBody)) {
                        logger.warn("Received SSH_MSG_REQUEST_SUCCESS with no pending global request")
                    }
                }

                SshEnums.MessageType.SSH_MSG_REQUEST_FAILURE -> {
                    if (!pendingGlobalRequest.complete(null)) {
                        logger.warn("Received SSH_MSG_REQUEST_FAILURE with no pending global request")
                    }
                }

                SshEnums.MessageType.SSH_MSG_DISCONNECT -> {
                    val msg = parseBody<SshMsgDisconnect>(packet)
                    logger.info("Received SSH_MSG_DISCONNECT from server: reason=${msg.reasonCode()}, description=${msg.description().value()}")
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.Disconnect)
                }

                else -> {
                    logger.warn("Unhandled message type: ${packet.messageType()}")
                }
            }
        }
    }

    // Helper methods for SSH protocol encoding

    /**
     * Read packets until we get the expected message type, skipping IGNORE/DEBUG messages.
     */
    private suspend inline fun <reified T> readExpectedMessage(expectedType: SshEnums.MessageType): T {
        while (true) {
            val packet = packetIO.readPacket()
            val messageType = packet.messageType()

            when (messageType) {
                SshEnums.MessageType.SSH_MSG_IGNORE -> {
                    logger.debug("Received SSH_MSG_IGNORE, skipping")
                    continue
                }

                SshEnums.MessageType.SSH_MSG_DEBUG -> {
                    logger.debug("Received SSH_MSG_DEBUG, skipping")
                    continue
                }

                expectedType -> {
                    return packet.body() as T
                }

                else -> {
                    throw SshException("Expected $expectedType but got $messageType")
                }
            }
        }
    }

    /**
     * Read packets until we get one of the expected message types, skipping IGNORE/DEBUG messages.
     */
    private suspend inline fun <reified T> readExpectedMessage(vararg expectedTypes: SshEnums.MessageType): T {
        while (true) {
            val packet = packetIO.readPacket()
            val messageType = packet.messageType()

            when (messageType) {
                SshEnums.MessageType.SSH_MSG_IGNORE -> {
                    logger.debug("Received SSH_MSG_IGNORE, skipping")
                    continue
                }

                SshEnums.MessageType.SSH_MSG_DEBUG -> {
                    logger.debug("Received SSH_MSG_DEBUG, skipping")
                    continue
                }

                in expectedTypes -> {
                    return packet as T
                }

                else -> {
                    throw SshException("Expected one of ${expectedTypes.joinToString()} but got $messageType")
                }
            }
        }
    }

    private inline fun <reified T : KaitaiStruct.ReadWrite> parseBody(packet: UnencryptedPacket.UnencryptedPayload): T {
        val rawBody = packet._raw_body()
        val stream = ByteBufferKaitaiStream(rawBody)
        val msg = T::class.java.getConstructor(io.kaitai.struct.KaitaiStream::class.java).newInstance(stream)
        msg._read()
        return msg
    }

    internal suspend fun sendChannelData(recipientChannel: Int, data: ByteArray) {
        val msg = SshMsgChannelData().apply {
            setRecipientChannel(recipientChannel.toLong())
            setData(createByteString(data))
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_DATA.id().toInt(),
            msg.toByteArray()
        )
    }

    internal suspend fun sendWindowAdjust(recipientChannel: Int, bytesToAdd: Int) {
        val msg = SshMsgChannelWindowAdjust().apply {
            setRecipientChannel(recipientChannel.toLong())
            setBytesToAdd(bytesToAdd.toLong())
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST.id().toInt(),
            msg.toByteArray()
        )
    }

    internal suspend fun sendChannelEof(recipientChannel: Int) {
        val msg = SshMsgChannelEof().apply {
            setRecipientChannel(recipientChannel.toLong())
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_EOF.id().toInt(),
            msg.toByteArray()
        )
    }

    private suspend fun checkAllChannelsClosed() {
        val allSessionsClosed = channels.values.all { !it.isOpen }
        val allForwardingClosed = forwardingChannels.values.all { !it.isOpen }
        val allAgentClosed = agentChannels.values.all { !it.isOpen }
        logger.debug("checkAllChannelsClosed: sessions=${channels.size} allSessionsClosed=$allSessionsClosed, forwarding=${forwardingChannels.size} allForwardingClosed=$allForwardingClosed, agent=${agentChannels.size} allAgentClosed=$allAgentClosed")
        if (allSessionsClosed && allForwardingClosed && allAgentClosed && channels.isNotEmpty()) {
            logger.info("All channels closed, sending disconnect")
            sendDisconnect()
        }
    }

    private suspend fun sendDisconnect() {
        logger.info("Sending disconnect (client-initiated)")
        try {
            val msg = SshMsgDisconnect().apply {
                setReasonCode(SshEnums.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION)
                setDescription(createUtf8String(""))
                setLanguage(createAsciiString(""))
                _check()
            }
            writePacket(
                SshEnums.MessageType.SSH_MSG_DISCONNECT.id().toInt(),
                msg.toByteArray()
            )
        } catch (e: Exception) {
            logger.debug("Failed to send disconnect", e)
        }
        _disconnectedFlow.tryEmit(null)
        transport.close()
    }

    private fun startPacketLoop() {
        if (packetLoopJob != null) return
        packetLoopJob = connectionScope.launch {
            var loopException: Exception? = null
            try {
                while (isActive) {
                    logger.debug("Packet loop: waiting for next packet")
                    processNextPacket()
                }
            } catch (_: CancellationException) {
                logger.debug("Packet loop cancelled")
            } catch (e: Exception) {
                val allClosed = channels.values.all { !it.isOpen }
                if (allClosed) {
                    logger.debug("Packet loop ended (all channels closed)")
                } else {
                    logger.warn("Packet loop ended unexpectedly", e)
                }
                loopException = e
            } finally {
                for (ch in channels.values) {
                    ch.onClose()
                }
                for (ch in forwardingChannels.values) {
                    ch.onClose()
                }
                val loopError = loopException ?: Exception("Packet loop terminated")
                withContext(stateMachineDispatcher) {
                    pendingAuth.completeExceptionally(loopError)
                    pendingChannelOpen.completeExceptionally(loopError)
                    pendingChannelRequest.completeExceptionally(loopError)
                    pendingGlobalRequest.completeExceptionally(loopError)
                    for ((_, pending) in pendingChannelOpens) {
                        pending.deferred.completeExceptionally(loopError)
                    }
                    pendingChannelOpens.clear()
                }
                if (loopException != null) {
                    _disconnectedFlow.tryEmit(loopException)
                }
            }
        }
    }

    private suspend fun stopPacketLoop() {
        packetLoopJob?.cancelAndJoin()
        packetLoopJob = null
    }

    // Channel management methods

    /**
     * Open a session channel (RFC 4254 section 6.1).
     *
     * @return SessionChannel instance if successful, null otherwise
     */
    suspend fun openSessionChannel(
        initialWindowSize: Int = 64 * 1024,
        maxPacketSize: Int = 32 * 1024,
    ): SessionChannel? {
        val localChannelNumber = allocateChannelNumber()

        logger.info("Opening session channel (local=$localChannelNumber)")

        val deferred = CompletableDeferred<SshMsgChannelOpenConfirmation?>()
        withContext(stateMachineDispatcher) {
            pendingChannelOpen.setDirect(deferred)
            stateMachine.processEvent(
                SshClientStateMachine.SshEvent.OpenChannel(
                    channelType = "session",
                    localChannelNumber = localChannelNumber,
                    initialWindowSize = initialWindowSize,
                    maxPacketSize = maxPacketSize
                )
            )
        }

        val confirmationMsg = try {
            deferred.await()
        } finally {
            pendingChannelOpen.clearIfSame(deferred)
        } ?: return null

        val remoteChannelNumber = confirmationMsg.senderChannel().toInt()
        val remoteWindow = confirmationMsg.initialWindowSize()
        logger.info("Channel opened: local=$localChannelNumber, remote=$remoteChannelNumber, remoteWindow=$remoteWindow")

        val channel = SessionChannel(
            this,
            connectionScope,
            localChannelNumber,
            remoteChannelNumber,
            maxPacketSize,
            remoteWindowSizeInitial = remoteWindow,
            initialWindowSize = initialWindowSize
        )
        channels[localChannelNumber] = channel
        channelsByRemote[localChannelNumber] = channel
        logger.debug("Session channel registered: local=$localChannelNumber, remote=$remoteChannelNumber (total channels: ${channels.size})")

        return channel
    }

    /**
     * Send a channel request (RFC 4254 section 5.4).
     *
     * @param recipientChannel Remote channel number
     * @param requestType Request type (e.g., "shell", "pty-req")
     * @param wantReply Whether to wait for a reply
     * @param configureRequest Lambda to configure request-specific fields
     * @return true if request succeeded (when wantReply=true), false otherwise
     */
    internal suspend fun sendChannelRequest(
        recipientChannel: Int,
        requestType: String,
        wantReply: Boolean,
        configureRequest: (SshMsgChannelRequest) -> Unit,
    ): Boolean {
        val msg = SshMsgChannelRequest().apply {
            setRecipientChannel(recipientChannel.toLong())
            setRequestType(createAsciiString(requestType))
            setWantReply(if (wantReply) 1 else 0)

            configureRequest(this)
            _check()
        }

        val deferred = if (wantReply) CompletableDeferred<Boolean>() else null
        withContext(stateMachineDispatcher) {
            if (deferred != null) {
                pendingChannelRequest.setDirect(deferred)
            }
            stateMachine.processEvent(
                SshClientStateMachine.SshEvent.SendChannelRequest(
                    recipientChannel = recipientChannel,
                    requestType = requestType,
                    wantReply = wantReply,
                    message = msg
                )
            )
        }

        if (deferred == null) {
            return true
        }

        return try {
            deferred.await()
        } finally {
            pendingChannelRequest.clearIfSame(deferred)
        }
    }

    /**
     * Send SSH_MSG_CHANNEL_CLOSE (RFC 4254 section 5.3).
     */
    internal suspend fun sendChannelClose(recipientChannel: Int) {
        val msg = SshMsgChannelClose().apply {
            setRecipientChannel(recipientChannel.toLong())
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE.id().toInt(),
            msg.toByteArray()
        )
    }
}

/**
 * Returns the list of password-based auth methods to attempt, in the order they should be tried.
 *
 * By default, `keyboard-interactive` is preferred when both methods are available.
 * When [preferPasswordAuth] is true and `password` is available, `password` is tried first;
 * `keyboard-interactive` is not tried when `password` is available and [preferPasswordAuth] is set.
 */
internal fun selectPasswordMethods(
    allowedMethods: Set<String>,
    preferPasswordAuth: Boolean,
): List<AuthMethod> {
    val parsed = allowedMethods.mapTo(mutableSetOf(), AuthMethod::fromString)
    val hasKbd = AuthMethod.KeyboardInteractive in parsed
    val hasPassword = AuthMethod.Password in parsed

    return when {
        hasKbd && hasPassword && preferPasswordAuth -> listOf(AuthMethod.Password)
        hasKbd && hasPassword -> listOf(AuthMethod.KeyboardInteractive)
        hasKbd -> listOf(AuthMethod.KeyboardInteractive)
        hasPassword -> listOf(AuthMethod.Password)
        else -> emptyList()
    }
}
