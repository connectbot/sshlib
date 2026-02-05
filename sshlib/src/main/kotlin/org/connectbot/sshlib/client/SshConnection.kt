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
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.crypto.*
import org.connectbot.sshlib.protocol.*
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshException
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.security.SecureRandom

/**
 * SSH connection handler that manages the protocol flow.
 *
 * This class ties together the state machine, transport layer, and crypto
 * implementations to handle a complete SSH connection lifecycle.
 *
 * @param transport Underlying transport (e.g., TCP socket)
 * @param clientVersion Client version string (default: SSH-2.0-CBSSH_1.0)
 */
class SshConnection(
    private val transport: Transport,
    private val clientVersion: String = "SSH-2.0-CBSSH_1.0",
    private val hostKeyVerifier: HostKeyVerifier,
    private val kexAlgorithms: String = KexEntry.defaultString,
    private val hostKeyAlgorithms: String = SignatureEntry.defaultString,
    private val encryptionAlgorithms: String = CipherEntry.defaultString,
    private val macAlgorithms: String = MacEntry.defaultString
) {

    companion object {
        private val logger = LoggerFactory.getLogger(SshConnection::class.java)
        private const val COMPRESSION_ALGORITHMS = "none"
    }

    private val packetIO = PacketIO(transport)
    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
    private val stateMachineDispatcher = newSingleThreadContext("ssh-state-machine")

    private val callbacks = object : SshClientCallbacks {
        override fun sendVersion() = this@SshConnection.sendVersion()
        override fun receiveVersion(banner: IdBanner) = this@SshConnection.receiveVersion(banner)
        override fun sendKexInit() = this@SshConnection.sendKexInit()
        override fun receiveKexInit(msg: SshMsgKexinit) = this@SshConnection.receiveKexInit(msg)
        override fun sendKexExchangeInit() = this@SshConnection.sendKexExchangeInit()
        override fun receiveKexDhReply(msg: SshMsgKexdhReply) = this@SshConnection.receiveKexDhReply(msg)
        override fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) = this@SshConnection.receiveKexEcdhReply(msg)
        override fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) = this@SshConnection.receiveKexDhGexReply(msg)
        override fun sendNewKeys() = this@SshConnection.sendNewKeys()
        override fun receiveNewKeys() = this@SshConnection.receiveNewKeys()
        override fun activateEncryption() = this@SshConnection.activateEncryption()
        override fun sendServiceRequest(service: String) = this@SshConnection.sendServiceRequest(service)
        override fun receiveServiceAccept(service: String) = this@SshConnection.receiveServiceAccept(service)
        override fun startAuthentication() = this@SshConnection.startAuthentication()
        override fun authenticationSuccess() = this@SshConnection.authenticationSuccess()
        override fun authenticationFailure() = this@SshConnection.authenticationFailure()
        override fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest) = this@SshConnection.receiveUserauthInfoRequest(msg)
        override fun receiveUserauthBanner(msg: SshMsgUserauthBanner) = this@SshConnection.receiveUserauthBanner(msg)
        override fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int) = this@SshConnection.sendChannelOpen(channelType, localChannelNumber, initialWindowSize, maxPacketSize)
        override fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) = this@SshConnection.receiveChannelOpenConfirmation(msg)
        override fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) = this@SshConnection.receiveChannelOpenFailure(msg)
        override fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) = this@SshConnection.sendChannelRequest(recipientChannel, requestType, wantReply, message)
        override fun receiveChannelSuccess() = this@SshConnection.receiveChannelSuccess()
        override fun receiveChannelFailure() = this@SshConnection.receiveChannelFailure()
        override fun receiveGlobalRequest(msg: SshMsgGlobalRequest) = this@SshConnection.receiveGlobalRequest(msg)
        override fun debug(msg: SshMsgDebug) = this@SshConnection.debug(msg)
        override fun ignore() = this@SshConnection.ignore()
        override fun disconnect() = this@SshConnection.disconnect()
        override fun onStateEnter(stateName: String) = this@SshConnection.onStateEnter(stateName)
        override fun onStateExit(stateName: String) = this@SshConnection.onStateExit(stateName)
    }

    private val stateMachine = SshClientStateMachine(callbacks)
    private val connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

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
    private var strictKexEnabled: Boolean = false

    private var nextLocalChannelNumber = 0
    private val channels = mutableMapOf<Int, SessionChannel>()
    private val channelsByRemote = mutableMapOf<Int, SessionChannel>()

    // Pending async operations - completed by callbacks
    private var pendingAuth: CompletableDeferred<Boolean>? = null
    private var pendingChannelOpen: CompletableDeferred<SshMsgChannelOpenConfirmation?>? = null
    private var pendingChannelRequest: CompletableDeferred<Boolean>? = null

    private var infoRequestChannel: Channel<SshMsgUserauthInfoRequest>? = null

    private var packetLoopJob: Job? = null

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun dispatchEvent(event: SshClientStateMachine.SshEvent) {
        withContext(stateMachineDispatcher) {
            stateMachine.processEvent(event)
        }
    }

    /**
     * Initiate SSH connection.
     * This is a blocking call that returns when authentication is complete.
     */
    fun connect(): Boolean = runBlocking {
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

                    val initMsg = SshMsgKexDhGexInit()
                    initMsg.setE(createMpint(clientPublicKey!!))
                    packetIO.writePacket(
                        SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_INIT.id().toInt(),
                        toByteArray(initMsg)
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
            return@runBlocking true
        } catch (e: Exception) {
            logger.error("SSH connection failed", e)
            return@runBlocking false
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
            val req = SshMsgUserauthRequest()
            req.setUserName(createAsciiString(username))
            req.setServiceName(createAsciiString("ssh-connection"))
            req.setMethodName(createAsciiString("password"))

            val passAuth = UserauthRequestPassword().apply {
                setChangePassword(0)
                setPlaintextPassword(createUtf8String(password))
                _check()
            }

            req.setMethodSpecificFields(passAuth)

            val deferred = CompletableDeferred<Boolean>()
            pendingAuth = deferred

            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                toByteArray(req)
            )

            return deferred.await()
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
        callback: KeyboardInteractiveCallback
    ): Boolean {
        try {
            val req = SshMsgUserauthRequest()
            req.setUserName(createAsciiString(username))
            req.setServiceName(createAsciiString("ssh-connection"))
            req.setMethodName(createAsciiString("keyboard-interactive"))

            val kbdInteractive = UserauthRequestKeyboardInteractive().apply {
                setLanguageTag(createByteString(ByteArray(0)))
                setSubmethods(createByteString(ByteArray(0)))
                _check()
            }
            req.setMethodSpecificFields(kbdInteractive)

            val deferred = CompletableDeferred<Boolean>()
            pendingAuth = deferred

            val channel = Channel<SshMsgUserauthInfoRequest>(Channel.UNLIMITED)
            infoRequestChannel = channel

            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                toByteArray(req)
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
                        val responseMsg = SshMsgUserauthInfoResponse()
                        responseMsg.setNumResponses(responses.size.toLong())
                        responseMsg.setResponses(responses.map { response ->
                            val bytes = response.toByteArray(Charsets.UTF_8)
                            createByteString(bytes)
                        })

                        packetIO.writePacket(
                            SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_61.id().toInt(),
                            toByteArray(responseMsg)
                        )
                    }
                }
            }

            try {
                return deferred.await()
            } finally {
                channel.close()
                consumerJob.cancel()
                infoRequestChannel = null
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
                sid, username, "ssh-connection", sigAlgorithmName, publicKeyBlob
            )

            // Sign the data
            val signature = sigEntry.algorithm.sign(
                sigAlgorithmName, privateKey.jcaKeyPair.private, signatureData
            )

            // Build the SSH_MSG_USERAUTH_REQUEST
            val req = SshMsgUserauthRequest()
            req.setUserName(createAsciiString(username))
            req.setServiceName(createAsciiString("ssh-connection"))
            req.setMethodName(createAsciiString("publickey"))
            req._check()

            val pubkeyAuth = UserauthRequestPublickey()
            pubkeyAuth.setHasSignature(1)
            pubkeyAuth.setPublicKeyAlgorithmName(createAsciiString(sigAlgorithmName))
            pubkeyAuth.setPublicKeyBlob(createByteString(publicKeyBlob))
            pubkeyAuth.setSignature(createByteString(signature))
            pubkeyAuth._check()

            req.setMethodSpecificFields(pubkeyAuth)

            val deferred = CompletableDeferred<Boolean>()
            pendingAuth = deferred

            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                toByteArray(req)
            )

            return deferred.await()
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
        publicKeyBlob: ByteArray
    ): ByteArray {
        val data = UserauthPublickeySignatureData()
        data.setSessionIdentifier(createByteString(sessionId))
        data.setMessageType(byteArrayOf(50))
        data.setUserName(createByteString(username.toByteArray(Charsets.UTF_8)))
        data.setServiceName(createByteString(serviceName.toByteArray(Charsets.US_ASCII)))
        data.setMethodName(createByteString("publickey".toByteArray(Charsets.US_ASCII)))
        data.setHasSignature(byteArrayOf(1))
        data.setPublicKeyAlgorithmName(createByteString(algorithmName.toByteArray(Charsets.US_ASCII)))
        data.setPublicKeyBlob(createByteString(publicKeyBlob))
        data._check()
        return toByteArray(data)
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

    private fun sendKexInit() {
        logger.debug("Sending KEX_INIT")

        val kexInit = SshMsgKexinit()

        // Cookie (16 random bytes)
        val cookie = ByteArray(16).apply {
            SecureRandom().nextBytes(this)
        }
        kexInit.setCookie(cookie)

        kexInit.setKexAlgorithms(createNameList(kexAlgorithms))
        kexInit.setServerHostKeyAlgorithms(createNameList(hostKeyAlgorithms))
        kexInit.setEncryptionAlgorithmsClientToServer(createNameList(encryptionAlgorithms))
        kexInit.setEncryptionAlgorithmsServerToClient(createNameList(encryptionAlgorithms))
        kexInit.setMacAlgorithmsClientToServer(createNameList(macAlgorithms))
        kexInit.setMacAlgorithmsServerToClient(createNameList(macAlgorithms))
        kexInit.setCompressionAlgorithmsClientToServer(createNameList(COMPRESSION_ALGORITHMS))
        kexInit.setCompressionAlgorithmsServerToClient(createNameList(COMPRESSION_ALGORITHMS))
        kexInit.setLanguagesClientToServer(createNameList(""))
        kexInit.setLanguagesServerToClient(createNameList(""))
        kexInit.setFirstKexPacketFollows(0)
        kexInit.setReserved(0)

        val kexInitPayload = toByteArray(kexInit)

        clientKexInit = byteArrayOf(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toByte()) + kexInitPayload

        runBlocking {
            packetIO.writePacket(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toInt(), kexInitPayload)
        }
    }

    private fun receiveKexInit(msg: SshMsgKexinit) {
        logger.info("Received KEX_INIT from server")

        val serverKexAlgs = msg.kexAlgorithms().entries().data()
        val serverHostKeyAlgs = msg.serverHostKeyAlgorithms().entries().data()
        val serverEncC2S = msg.encryptionAlgorithmsClientToServer().entries().data()
        val serverEncS2C = msg.encryptionAlgorithmsServerToClient().entries().data()
        val serverMacC2S = msg.macAlgorithmsClientToServer().entries().data()
        val serverMacS2C = msg.macAlgorithmsServerToClient().entries().data()

        logger.debug("  Server KEX algorithms: $serverKexAlgs")
        logger.debug("  Server host key algorithms: $serverHostKeyAlgs")
        logger.debug("  Server encryption c->s: $serverEncC2S")
        logger.debug("  Server encryption s->c: $serverEncS2C")
        logger.debug("  Server MAC c->s: $serverMacC2S")
        logger.debug("  Server MAC s->c: $serverMacS2C")

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
    }

    private fun sendKexExchangeInit() {
        val kexName = negotiatedKex ?: throw SshException("No KEX algorithm negotiated")
        val kexEntry = KexEntry.fromSshName(kexName)
            ?: throw SshException("Unknown KEX algorithm: $kexName")
        when (kexEntry.type) {
            KexType.ECDH -> sendKexEcdhInit(kexEntry)
            KexType.DH -> sendKexDhInit(kexEntry)
            KexType.DH_GEX -> sendKexDhGexRequest(kexEntry)
        }
    }

    private fun sendKexDhInit(kexEntry: KexEntry) {
        logger.debug("Sending DH_INIT")

        val dh = kexEntry.create()
        kex = dh
        clientPublicKey = dh.generateClientKeys()

        val pubKey = clientPublicKey
            ?: throw SshException("Client public key not generated")

        val msg = SshMsgKexdhInit()
        msg.setE(createMpint(pubKey))

        runBlocking {
            packetIO.writePacket(SshEnums.KexDh.SSH_MSG_KEXDH_INIT.id().toInt(), toByteArray(msg))
        }
    }

    private fun sendKexEcdhInit(kexEntry: KexEntry) {
        logger.debug("Sending ECDH_INIT (${kexEntry.sshName})")

        val ecdh = kexEntry.create()
        kex = ecdh
        clientPublicKey = ecdh.generateClientKeys()

        val pubKey = clientPublicKey
            ?: throw SshException("Client public key not generated")

        val msg = SshMsgKexEcdhInit()
        msg.setQC(createByteString(pubKey))

        runBlocking {
            packetIO.writePacket(SshEnums.KexEcdh.SSH_MSG_KEX_ECDH_INIT.id().toInt(), toByteArray(msg))
        }
    }

    private fun sendKexDhGexRequest(kexEntry: KexEntry) {
        logger.debug("Sending DH_GEX_REQUEST (${kexEntry.sshName})")

        val dhGex = kexEntry.create() as DiffieHellmanGroupExchange
        kex = dhGex

        val msg = SshMsgKexDhGexRequest()
        msg.setMin(dhGex.min.toLong())
        msg.setN(dhGex.n.toLong())
        msg.setMax(dhGex.max.toLong())

        runBlocking {
            packetIO.writePacket(SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_REQUEST.id().toInt(), toByteArray(msg))
        }
    }

    private fun receiveKexDhReply(msg: SshMsgKexdhReply) {
        logger.info("Received DH_REPLY from server")
        completeKex(
            serverHostKey = msg.serverKey().data(),
            serverPublicKey = msg.f().body(),
            signature = msg.signatureH().data()
        )
    }

    private fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) {
        logger.info("Received ECDH_REPLY from server")
        completeKex(
            serverHostKey = msg.kS().data(),
            serverPublicKey = msg.qS().data(),
            signature = msg.signatureH().data()
        )
    }

    private fun completeKex(serverHostKey: ByteArray, serverPublicKey: ByteArray, signature: ByteArray) {
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

        val trusted = runBlocking {
            hostKeyVerifier.verify(publicKey)
        }

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

    private fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) {
        logger.info("Received DH_GEX_REPLY from server")
        completeKex(
            serverHostKey = msg.serverPublicHostKey().data(),
            serverPublicKey = msg.f().body(),
            signature = msg.signatureH().data()
        )
    }

    private fun sendNewKeys() {
        logger.debug("Sending NEW_KEYS")
        runBlocking {
            packetIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt())
            if (strictKexEnabled) {
                packetIO.resetSendSequenceNumber()
            }
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

    private fun sendServiceRequest(service: String) {
        logger.info("Requesting service: $service")

        val msg = SshMsgServiceRequest()
        msg.setServiceName(createAsciiString(service))

        runBlocking {
            packetIO.writePacket(SshEnums.MessageType.SSH_MSG_SERVICE_REQUEST.id().toInt(), toByteArray(msg))
        }
    }

    private fun receiveServiceAccept(service: String) {
        logger.info("Service accepted: $service")
    }

    private fun startAuthentication() {
        logger.info("Starting authentication")
    }

    private fun authenticationSuccess() {
        logger.info("Authentication successful")
        pendingAuth?.complete(true)
        pendingAuth = null
    }

    private fun authenticationFailure() {
        logger.warn("Authentication failed")
        pendingAuth?.complete(false)
        pendingAuth = null
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

    private fun disconnect() {
        logger.info("Disconnecting")
        runBlocking {
            transport.close()
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
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

    private fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int) {
        logger.debug("Sending CHANNEL_OPEN: $channelType (local=$localChannelNumber)")

        val msg = SshMsgChannelOpen()
        msg.setChannelType(createAsciiString(channelType))
        msg.setSenderChannel(localChannelNumber.toLong())
        msg.setInitialWindowSize(initialWindowSize.toLong())
        msg.setMaximumPacketSize(maxPacketSize.toLong())

        val sessionData = ChannelOpenSession()
        sessionData._check()
        msg.setChannelSpecificData(sessionData)

        runBlocking {
            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN.id().toInt(),
                toByteArray(msg)
            )
        }
    }

    private fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) {
        logger.info("Channel open confirmed")
        pendingChannelOpen?.complete(msg)
        pendingChannelOpen = null
    }

    private fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) {
        logger.error("Channel open failed: ${msg.reasonCode()}")
        pendingChannelOpen?.complete(null)
        pendingChannelOpen = null
    }

    private fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) {
        logger.debug("Sending CHANNEL_REQUEST: $requestType (channel=$recipientChannel, wantReply=$wantReply)")

        runBlocking {
            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST.id().toInt(),
                toByteArray(message)
            )
        }
    }

    private fun receiveChannelSuccess() {
        logger.debug("Channel request succeeded")
        pendingChannelRequest?.complete(true)
        pendingChannelRequest = null
    }

    private fun receiveChannelFailure() {
        logger.warn("Channel request failed")
        pendingChannelRequest?.complete(false)
        pendingChannelRequest = null
    }

    private fun receiveGlobalRequest(msg: SshMsgGlobalRequest) {
        val requestName = msg.requestName().value()
        val wantReply = msg.wantReply() != 0

        logger.debug("Received global request: $requestName (want_reply=$wantReply)")

        // Note: Sending response should be done by the caller in the coroutine context
        // For now, we just log it and let the server timeout if it wants a reply
        if (wantReply) {
            logger.warn("Global request wants reply but we don't handle it: $requestName")
            // TODO: Send SSH_MSG_REQUEST_FAILURE asynchronously
        }
    }

    // Packet processing

    /**
     * Read and dispatch the next packet through the state machine.
     * This is the central packet processing loop that converts packets to events.
     */
    private suspend fun processNextPacket() {
        val packet = packetIO.readPacket()
        logger.debug("Received message type ${packet.messageType()}")

        when (packet.messageType()) {
            SshEnums.MessageType.SSH_MSG_IGNORE -> {
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveIgnore)
            }
            SshEnums.MessageType.SSH_MSG_DEBUG -> {
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveDebug(packet.body() as SshMsgDebug))
            }
            SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST -> {
                try {
                    val rawBody = packet._raw_body()
                    val stream = ByteBufferKaitaiStream(rawBody)
                    val globalRequestMsg = SshMsgGlobalRequest(stream)
                    globalRequestMsg._read()
                    dispatchEvent(SshClientStateMachine.SshEvent.ReceiveGlobalRequest(globalRequestMsg))
                } catch (e: Exception) {
                    logger.error("Failed to parse SSH_MSG_GLOBAL_REQUEST", e)
                }
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> {
                val messageTypeByte = packet.messageType().id().toByte()
                val rawBody = byteArrayOf(messageTypeByte) + packet._raw_body()
                val stream = ByteBufferKaitaiStream(rawBody)
                val confirmationMsg = SshMsgChannelOpenConfirmation(stream)
                confirmationMsg._read()
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveChannelOpenConfirmation(confirmationMsg))
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE -> {
                val messageTypeByte = packet.messageType().id().toByte()
                val rawBody = byteArrayOf(messageTypeByte) + packet._raw_body()
                val stream = ByteBufferKaitaiStream(rawBody)
                val failureMsg = SshMsgChannelOpenFailure(stream)
                failureMsg._read()
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveChannelOpenFailure(failureMsg))
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_DATA -> {
                val msg = parseBody<SshMsgChannelData>(packet)
                val channel = channelsByRemote[msg.recipientChannel().toInt()]
                if (channel != null) {
                    channel.onData(msg.data().data())
                } else {
                    logger.warn("Data for unknown channel ${msg.recipientChannel()}")
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
                val channel = channelsByRemote[msg.recipientChannel().toInt()]
                if (channel != null) {
                    channel.onWindowAdjust(msg.bytesToAdd())
                } else {
                    logger.warn("Window adjust for unknown channel ${msg.recipientChannel()}")
                }
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_EOF -> {
                val msg = parseBody<SshMsgChannelEof>(packet)
                val channel = channelsByRemote[msg.recipientChannel().toInt()]
                if (channel != null) {
                    channel.onEof()
                } else {
                    logger.warn("EOF for unknown channel ${msg.recipientChannel()}")
                }
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE -> {
                val msg = parseBody<SshMsgChannelClose>(packet)
                val channel = channelsByRemote[msg.recipientChannel().toInt()]
                if (channel != null) {
                    channel.onClose()
                } else {
                    logger.warn("Close for unknown channel ${msg.recipientChannel()}")
                }
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST -> {
                val rawBody = packet._raw_body()
                val stream = ByteBufferKaitaiStream(rawBody)
                val msg = SshMsgChannelRequest(stream)
                msg._read()
                logger.debug("Received channel request: ${msg.requestType().value()} (want_reply=${msg.wantReply() != 0})")
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_SUCCESS -> {
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveChannelSuccess)
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_FAILURE -> {
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveChannelFailure)
            }
            SshEnums.MessageType.SSH_MSG_USERAUTH_SUCCESS -> {
                dispatchEvent(SshClientStateMachine.SshEvent.AuthenticationSuccess)
            }
            SshEnums.MessageType.SSH_MSG_USERAUTH_FAILURE -> {
                dispatchEvent(SshClientStateMachine.SshEvent.AuthenticationFailure)
            }
            SshEnums.MessageType.SSH_MSG_USERAUTH_BANNER -> {
                val msg = parseBody<SshMsgUserauthBanner>(packet)
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveUserauthBanner(msg))
            }
            SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_60 -> {
                val msg = parseBody<SshMsgUserauthInfoRequest>(packet)
                dispatchEvent(SshClientStateMachine.SshEvent.ReceiveUserauthInfoRequest(msg))
            }
            SshEnums.MessageType.SSH_MSG_DISCONNECT -> {
                dispatchEvent(SshClientStateMachine.SshEvent.Disconnect)
            }
            else -> {
                logger.warn("Unhandled message type: ${packet.messageType()}")
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

    private fun toByteArray(struct: KaitaiStruct.ReadWrite): ByteArray {
        struct._check()
        val io = ByteBufferKaitaiStream(1024 * 32)
        struct._write(io)
        val size = io.pos()
        io.seek(0)
        return io.readBytes(size.toLong())
    }

    private fun createAsciiString(str: String): AsciiString {
        val s = AsciiString()
        s.setLen(str.length.toLong())
        s.setValue(str)
        s._check()
        return s
    }

    private fun createUtf8String(str: String): Utf8String {
        val bytes = str.toByteArray(Charsets.UTF_8)
        val s = Utf8String()
        s.setLen(bytes.size.toLong())
        s.setValue(str)
        s._check()
        return s
    }

    private fun createNameList(names: String): NameList {
        val nameList = NameList()
        val entries = NameList.NameEntry()
        entries.set_parent(nameList)
        entries.set_root(nameList)

        if (names.isEmpty()) {
            entries.setData(emptyList())
            nameList.setLenEntries(0)
        } else {
            val list = names.split(",")
            entries.setData(list)
            val contentBytes = names.toByteArray(Charsets.US_ASCII)
            nameList.setLenEntries(contentBytes.size.toLong())
        }

        entries._check()
        nameList.setEntries(entries)
        nameList._check()
        return nameList
    }

    private fun createMpint(data: ByteArray): Mpint {
        var start = 0
        while (start < data.size - 1 && data[start] == 0.toByte()) {
            start++
        }

        val needsPadding = (data[start].toInt() and 0x80) != 0

        val formattedLength = data.size - start + if (needsPadding) 1 else 0
        val formatted = ByteArray(formattedLength)

        if (needsPadding) {
            formatted[0] = 0
            System.arraycopy(data, start, formatted, 1, data.size - start)
        } else {
            System.arraycopy(data, start, formatted, 0, data.size - start)
        }

        val m = Mpint()
        m.setLenBody(formattedLength.toLong())
        m.setBody(formatted)
        m._check()
        return m
    }

    private fun createByteString(data: ByteArray): ByteString {
        val bs = ByteString()
        bs.setLenData(data.size.toLong())
        bs.setData(data)
        bs._check()
        return bs
    }

    private inline fun <reified T : KaitaiStruct.ReadWrite> parseBody(packet: UnencryptedPacket.UnencryptedPayload): T {
        val rawBody = packet._raw_body()
        val stream = ByteBufferKaitaiStream(rawBody)
        val msg = T::class.java.getConstructor(io.kaitai.struct.KaitaiStream::class.java).newInstance(stream)
        msg._read()
        return msg
    }

    internal suspend fun sendChannelData(recipientChannel: Int, data: ByteArray) {
        val msg = SshMsgChannelData()
        msg.setRecipientChannel(recipientChannel.toLong())
        msg.setData(createByteString(data))

        packetIO.writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_DATA.id().toInt(),
            toByteArray(msg)
        )
    }

    internal suspend fun sendWindowAdjust(recipientChannel: Int, bytesToAdd: Int) {
        val msg = SshMsgChannelWindowAdjust()
        msg.setRecipientChannel(recipientChannel.toLong())
        msg.setBytesToAdd(bytesToAdd.toLong())

        packetIO.writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST.id().toInt(),
            toByteArray(msg)
        )
    }

    internal suspend fun sendChannelEof(recipientChannel: Int) {
        val msg = SshMsgChannelEof()
        msg.setRecipientChannel(recipientChannel.toLong())

        packetIO.writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_EOF.id().toInt(),
            toByteArray(msg)
        )
    }

    private fun startPacketLoop() {
        if (packetLoopJob != null) return
        packetLoopJob = connectionScope.launch {
            try {
                while (isActive) {
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
            } finally {
                channels.values.forEach { it.onClose() }
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
        initialWindowSize: Int = 64 * 1024, // 64KiB
        maxPacketSize: Int = 32 * 1024  // 32KiB
    ): SessionChannel? {
        val localChannelNumber = nextLocalChannelNumber++

        logger.info("Opening session channel (local=$localChannelNumber)")

        val deferred = CompletableDeferred<SshMsgChannelOpenConfirmation?>()
        pendingChannelOpen = deferred

        dispatchEvent(SshClientStateMachine.SshEvent.OpenChannel(
            channelType = "session",
            localChannelNumber = localChannelNumber,
            initialWindowSize = initialWindowSize,
            maxPacketSize = maxPacketSize
        ))

        val confirmationMsg = deferred.await() ?: return null

        val remoteChannelNumber = confirmationMsg.senderChannel().toInt()
        val remoteWindow = confirmationMsg.initialWindowSize()
        logger.info("Channel opened: local=$localChannelNumber, remote=$remoteChannelNumber, remoteWindow=$remoteWindow")

        val channel = SessionChannel(
            this,
            localChannelNumber,
            remoteChannelNumber,
            maxPacketSize,
            remoteWindowSize = remoteWindow,
            initialWindowSize = initialWindowSize
        )
        channels[localChannelNumber] = channel
        channelsByRemote[localChannelNumber] = channel

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
        configureRequest: (SshMsgChannelRequest) -> Unit
    ): Boolean {
        val msg = SshMsgChannelRequest()
        msg.setRecipientChannel(recipientChannel.toLong())
        msg.setRequestType(createAsciiString(requestType))
        msg.setWantReply(if (wantReply) 1 else 0)

        configureRequest(msg)

        val deferred = if (wantReply) {
            CompletableDeferred<Boolean>().also { pendingChannelRequest = it }
        } else null

        dispatchEvent(SshClientStateMachine.SshEvent.SendChannelRequest(
            recipientChannel = recipientChannel,
            requestType = requestType,
            wantReply = wantReply,
            message = msg
        ))

        if (deferred == null) {
            return true
        }

        return deferred.await()
    }

    /**
     * Send SSH_MSG_CHANNEL_CLOSE (RFC 4254 section 5.3).
     */
    internal suspend fun sendChannelClose(recipientChannel: Int) {
        val msg = SshMsgChannelClose()
        msg.setRecipientChannel(recipientChannel.toLong())

        packetIO.writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE.id().toInt(),
            toByteArray(msg)
        )
    }
}
