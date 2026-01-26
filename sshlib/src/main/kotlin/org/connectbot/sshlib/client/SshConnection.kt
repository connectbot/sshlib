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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.crypto.*
import org.connectbot.sshlib.struct.*
import org.connectbot.sshlib.struct.SshClientCallbacks
import org.connectbot.sshlib.struct.SshClientStateMachine
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.Transport
import org.slf4j.LoggerFactory

/**
 * SSH connection handler that manages the protocol flow.
 *
 * This class ties together the state machine, transport layer, and crypto
 * implementations to handle a complete SSH connection lifecycle.
 *
 * @param transport Underlying transport (e.g., TCP socket)
 * @param clientVersion Client version string (default: SSH-2.0-SshProtoClient_1.0)
 */
class SshConnection(
    private val transport: Transport,
    private val clientVersion: String = "SSH-2.0-SshProtoClient_1.0"
) : SshClientCallbacks {

    companion object {
        private val logger = LoggerFactory.getLogger(SshConnection::class.java)

        // Supported algorithms (minimal initial implementation)
        // Note: kex-strict-c-v00@openssh.com is a marker for strict KEX support (RFC draft-ietf-sshm-strict-kex)
        private const val KEX_ALGORITHMS = "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,kex-strict-c-v00@openssh.com"
        private const val HOST_KEY_ALGORITHMS = "rsa-sha2-256,rsa-sha2-512,ssh-rsa"
        private const val ENCRYPTION_ALGORITHMS = "aes128-ctr,aes256-ctr"
        private const val MAC_ALGORITHMS = "hmac-sha2-256,hmac-sha2-512"
        private const val COMPRESSION_ALGORITHMS = "none"
    }

    private val packetIO = PacketIO(transport)
    private val stateMachine = SshClientStateMachine(this)

    private var serverVersion: String? = null
    private var clientKexInit: ByteArray? = null
    private var serverKexInit: ByteArray? = null

    private val dh = DiffieHellman()
    private var clientPublicKey: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var exchangeHash: ByteArray? = null
    private var sessionId: ByteArray? = null

    private var nextLocalChannelNumber = 0
    private val channels = mutableMapOf<Int, SessionChannel>()

    // Pending async operations - completed by callbacks
    private var pendingChannelOpen: CompletableDeferred<SshMsgChannelOpenConfirmation?>? = null
    private var pendingChannelRequest: CompletableDeferred<Boolean>? = null

    /**
     * Initiate SSH connection.
     * This is a blocking call that returns when authentication is complete.
     */
    fun connect(): Boolean = runBlocking {
        try {
            stateMachine.processEvent(SshClientStateMachine.SshEvent.Connect)

            // Version exchange
            packetIO.writeBanner(clientVersion)
            val banner = packetIO.readBanner()
            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveVersion(banner))

            // Key exchange initialization - read server's KEXINIT
            val kexInitPacket = packetIO.readPacket()
            val kexInit = kexInitPacket.body() as SshMsgKexinit

            // Save raw KEXINIT payload for exchange hash (message type + body)
            val kexInitMsgType = kexInitPacket.messageType().id().toByte()
            serverKexInit = byteArrayOf(kexInitMsgType) + kexInitPacket._raw_body()

            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveKexInit(kexInit))
            // Note: ReceiveKexInit transition triggers sendKexDhInit() via state machine

            // Diffie-Hellman key exchange - read server's DH_REPLY
            // KEX-specific messages (30-49) need special parsing based on negotiated algorithm
            val dhReplyPacket = packetIO.readPacket()

            // Re-parse as KEXDH payload since we negotiated diffie-hellman-group14
            // _raw_body() excludes the message type byte, so we need to prepend it
            val messageTypeByte = dhReplyPacket.messageType().id().toByte()
            val rawBody = byteArrayOf(messageTypeByte) + dhReplyPacket._raw_body()
            val kexdhStream = ByteBufferKaitaiStream(rawBody)
            val kexdhPayload = KexdhPayload(kexdhStream)
            kexdhPayload._read()
            val dhReply = kexdhPayload.body() as SshMsgKexdhReply

            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveKex.DhReply(dhReply))
            // Note: ReceiveKex.DhReply transition triggers sendNewKeys() via state machine

            // New keys - read server's NEWKEYS
            val newKeysPacket = packetIO.readPacket()
            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveNewKeys)

            // Service request (ssh-userauth)
            // Loop until we get SERVICE_ACCEPT (skip IGNORE/DEBUG messages)
            val serviceAccept = readExpectedMessage<SshMsgServiceAccept>(
                SshEnums.MessageType.SSH_MSG_SERVICE_ACCEPT
            )
            stateMachine.processEvent(
                SshClientStateMachine.SshEvent.ReceiveServiceAccept(serviceAccept.serviceName().value())
            )

            logger.info("SSH connection established successfully")
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

            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                toByteArray(req)
            )

            // Wait for response
            val response = packetIO.readPacket()
            return when (response.messageType()) {
                SshEnums.MessageType.SSH_MSG_USERAUTH_SUCCESS -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.AuthenticationSuccess)
                    logger.info("Authentication successful")
                    true
                }
                SshEnums.MessageType.SSH_MSG_USERAUTH_FAILURE -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.AuthenticationFailure)
                    logger.warn("Authentication failed")
                    false
                }
                else -> {
                    logger.warn("Unexpected message type during auth: ${response.messageType()}")
                    false
                }
            }
        } catch (e: Exception) {
            logger.error("Authentication error", e)
            return false
        }
    }

    // SshClientCallbacks implementation

    override fun sendVersion() {
        logger.debug("Sending version: $clientVersion")
    }

    override fun receiveVersion(banner: IdBanner) {
        // protoVersion() includes everything after "SSH-" up to and including \r\n
        // For exchange hash, we need "SSH-" + version without the CR-LF
        val versionWithCrlf = banner.protoVersion()
        val versionClean = versionWithCrlf.trimEnd('\r', '\n')
        serverVersion = "SSH-$versionClean"
        logger.info("Server version: $serverVersion")
    }

    override fun sendKexInit() {
        logger.debug("Sending KEX_INIT")

        val kexInit = SshMsgKexinit()

        // Cookie (16 random bytes)
        val cookie = ByteArray(16).apply {
            java.security.SecureRandom().nextBytes(this)
        }
        kexInit.setCookie(cookie)

        kexInit.setKexAlgorithms(createNameList(KEX_ALGORITHMS))
        kexInit.setServerHostKeyAlgorithms(createNameList(HOST_KEY_ALGORITHMS))
        kexInit.setEncryptionAlgorithmsClientToServer(createNameList(ENCRYPTION_ALGORITHMS))
        kexInit.setEncryptionAlgorithmsServerToClient(createNameList(ENCRYPTION_ALGORITHMS))
        kexInit.setMacAlgorithmsClientToServer(createNameList(MAC_ALGORITHMS))
        kexInit.setMacAlgorithmsServerToClient(createNameList(MAC_ALGORITHMS))
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

    override fun receiveKexInit(msg: SshMsgKexinit) {
        logger.info("Received KEX_INIT from server")

        val serverKexAlgs = msg.kexAlgorithms().entries().data()
        val serverEncryptionAlgs = msg.encryptionAlgorithmsClientToServer().entries().data()
        val serverMacAlgs = msg.macAlgorithmsClientToServer().entries().data()

        logger.debug("  Server KEX algorithms: $serverKexAlgs")
        logger.debug("  Server encryption c->s: $serverEncryptionAlgs")
        logger.debug("  Server MAC c->s: $serverMacAlgs")

        // Find first matching KEX algorithm
        val clientKexList = KEX_ALGORITHMS.split(",")
        val matchingKex = clientKexList.firstOrNull { it in serverKexAlgs }
        logger.info("  Negotiated KEX: $matchingKex")

        if (matchingKex == null) {
            logger.error("No matching KEX algorithm! Client: $KEX_ALGORITHMS, Server: $serverKexAlgs")
        }
    }

    override fun sendKexDhInit() {
        logger.debug("Sending DH_INIT")

        // Generate client's DH key pair
        clientPublicKey = dh.generateClientKeys()

        val msg = SshMsgKexdhInit()
        msg.setE(createMpint(clientPublicKey!!))

        runBlocking {
            packetIO.writePacket(SshEnums.KexDh.SSH_MSG_KEXDH_INIT.id().toInt(), toByteArray(msg))
        }
    }

    override fun receiveKexDhReply(msg: SshMsgKexdhReply) {
        logger.info("Received DH_REPLY from server")

        // Extract server's public key and signature
        val serverHostKey = msg.serverKey().data()
        val serverPublicKey = msg.f().body()
        val signature = msg.signatureH().data()

        // Compute shared secret
        sharedSecret = dh.computeSharedSecret(serverPublicKey)

        // Compute exchange hash
        exchangeHash = dh.computeExchangeHash(
            clientVersion.toByteArray(),
            serverVersion!!.toByteArray(),
            clientKexInit!!,
            serverKexInit!!,
            serverHostKey,
            clientPublicKey!!,
            serverPublicKey,
            sharedSecret!!
        )

        // Session ID is the exchange hash from first key exchange
        if (sessionId == null) {
            sessionId = exchangeHash
        }

        // TODO: Verify server's signature over exchange hash
        logger.debug("Shared secret computed, exchange hash calculated")
    }

    override fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) {
        logger.warn("ECDH not implemented yet")
    }

    override fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) {
        logger.warn("DH-GEX not implemented yet")
    }

    override fun sendNewKeys() {
        logger.debug("Sending NEW_KEYS")
        runBlocking {
            packetIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt())
            // TODO check if we're using strict KEX
            packetIO.resetSendSequenceNumber()
        }
    }

    override fun receiveNewKeys() {
        logger.info("Received NEW_KEYS from server")
        // TODO check if we're using strict KEX
        packetIO.resetReceiveSequenceNumber()
    }

    override fun activateEncryption() {
        logger.info("Activating encryption")

        // Derive keys using SHA-256 (for diffie-hellman-group14-sha256)
        val keyDerivation = KeyDerivation(
            sharedSecret!!,
            exchangeHash!!,
            sessionId!!,
            "SHA-256"
        )

        val keys = keyDerivation.deriveKeys(
            ivLength = 16,      // AES block size
            keyLength = 16,     // AES-128
            macKeyLength = 32   // HMAC-SHA256
        )


        // Create ciphers and MACs for both directions
        val clientToServerCipher = AesCtrCipher(keys.encryptionKeyClientToServer, keys.initialIvClientToServer, forEncryption = true)
        val clientToServerMac = HmacSha256(keys.integrityKeyClientToServer)
        val serverToClientCipher = AesCtrCipher(keys.encryptionKeyServerToClient, keys.initialIvServerToClient, forEncryption = false)
        val serverToClientMac = HmacSha256(keys.integrityKeyServerToClient)

        // Enable encryption in PacketIO
        packetIO.enableEncryption(
            clientToServerCipher,
            clientToServerMac,
            serverToClientCipher,
            serverToClientMac
        )

        logger.info("Encryption active")
    }

    override fun sendServiceRequest(service: String) {
        logger.info("Requesting service: $service")

        val msg = SshMsgServiceRequest()
        msg.setServiceName(createAsciiString(service))

        runBlocking {
            packetIO.writePacket(SshEnums.MessageType.SSH_MSG_SERVICE_REQUEST.id().toInt(), toByteArray(msg))
        }
    }

    override fun receiveServiceAccept(service: String) {
        logger.info("Service accepted: $service")
    }

    override fun startAuthentication() {
        logger.info("Starting authentication")
    }

    override fun authenticationSuccess() {
        logger.info("Authentication successful")
    }

    override fun authenticationFailure() {
        logger.warn("Authentication failed")
    }

    override fun debug(msg: SshMsgDebug) {
        logger.debug("SSH debug: ${msg.message()}")
    }

    override fun ignore() {
        logger.trace("Received IGNORE message")
    }

    override fun disconnect() {
        logger.info("Disconnecting")
        runBlocking {
            transport.close()
        }
    }

    override fun onStateEnter(stateName: String) {
        logger.debug("State: $stateName")
    }

    override fun onStateExit(stateName: String) {
        // Not logging state exits to reduce verbosity
    }

    override fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int) {
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

    override fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) {
        logger.info("Channel open confirmed")
        pendingChannelOpen?.complete(msg)
        pendingChannelOpen = null
    }

    override fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) {
        logger.error("Channel open failed: ${msg.reasonCode()}")
        pendingChannelOpen?.complete(null)
        pendingChannelOpen = null
    }

    override fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) {
        logger.debug("Sending CHANNEL_REQUEST: $requestType (channel=$recipientChannel, wantReply=$wantReply)")

        runBlocking {
            packetIO.writePacket(
                SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST.id().toInt(),
                toByteArray(message)
            )
        }
    }

    override fun receiveChannelSuccess() {
        logger.debug("Channel request succeeded")
        pendingChannelRequest?.complete(true)
        pendingChannelRequest = null
    }

    override fun receiveChannelFailure() {
        logger.warn("Channel request failed")
        pendingChannelRequest?.complete(false)
        pendingChannelRequest = null
    }

    override fun receiveGlobalRequest(msg: SshMsgGlobalRequest) {
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
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> {
                val messageTypeByte = packet.messageType().id().toByte()
                val rawBody = byteArrayOf(messageTypeByte) + packet._raw_body()
                val stream = ByteBufferKaitaiStream(rawBody)
                val confirmationMsg = SshMsgChannelOpenConfirmation(stream)
                confirmationMsg._read()
                stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelOpenConfirmation(confirmationMsg))
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE -> {
                val messageTypeByte = packet.messageType().id().toByte()
                val rawBody = byteArrayOf(messageTypeByte) + packet._raw_body()
                val stream = ByteBufferKaitaiStream(rawBody)
                val failureMsg = SshMsgChannelOpenFailure(stream)
                failureMsg._read()
                stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelOpenFailure(failureMsg))
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST -> {
                logger.debug("Received SSH_MSG_CHANNEL_WINDOW_ADJUST")
                // TODO: Update channel window size
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_SUCCESS -> {
                stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelSuccess)
            }
            SshEnums.MessageType.SSH_MSG_CHANNEL_FAILURE -> {
                stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveChannelFailure)
            }
            SshEnums.MessageType.SSH_MSG_DISCONNECT -> {
                stateMachine.processEvent(SshClientStateMachine.SshEvent.Disconnect)
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
                    throw IllegalStateException("Expected $expectedType but got $messageType")
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
                    throw IllegalStateException("Expected one of ${expectedTypes.joinToString()} but got $messageType")
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

        stateMachine.processEvent(SshClientStateMachine.SshEvent.OpenChannel(
            channelType = "session",
            localChannelNumber = localChannelNumber,
            initialWindowSize = initialWindowSize,
            maxPacketSize = maxPacketSize
        ))

        // Process packets until the pending operation completes
        while (!deferred.isCompleted) {
            processNextPacket()
        }

        val confirmationMsg = deferred.await() ?: return null

        val remoteChannelNumber = confirmationMsg.senderChannel().toInt()
        logger.info("Channel opened: local=$localChannelNumber, remote=$remoteChannelNumber")

        val channel = SessionChannel(
            this,
            localChannelNumber,
            remoteChannelNumber,
            maxPacketSize
        )
        channels[localChannelNumber] = channel
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

        stateMachine.processEvent(SshClientStateMachine.SshEvent.SendChannelRequest(
            recipientChannel = recipientChannel,
            requestType = requestType,
            wantReply = wantReply,
            message = msg
        ))

        if (deferred == null) {
            return true
        }

        // Process packets until the pending operation completes
        while (!deferred.isCompleted) {
            processNextPacket()
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
