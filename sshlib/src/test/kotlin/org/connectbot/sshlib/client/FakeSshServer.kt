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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.connectbot.sshlib.crypto.CipherEntry
import org.connectbot.sshlib.crypto.EncryptionInstance
import org.connectbot.sshlib.crypto.KeyDerivation
import org.connectbot.sshlib.crypto.MacEntry
import org.connectbot.sshlib.crypto.SshPublicKeyEncoder
import org.connectbot.sshlib.crypto.X25519ProviderFactory
import org.connectbot.sshlib.crypto.encodeMpint
import org.connectbot.sshlib.protocol.SshEnums
import org.connectbot.sshlib.protocol.SshMsgChannelData
import org.connectbot.sshlib.protocol.SshMsgChannelFailure
import org.connectbot.sshlib.protocol.SshMsgChannelOpen
import org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation
import org.connectbot.sshlib.protocol.SshMsgChannelOpenFailure
import org.connectbot.sshlib.protocol.SshMsgChannelRequest
import org.connectbot.sshlib.protocol.SshMsgChannelSuccess
import org.connectbot.sshlib.protocol.SshMsgDisconnect
import org.connectbot.sshlib.protocol.SshMsgExtInfo
import org.connectbot.sshlib.protocol.SshMsgIgnore
import org.connectbot.sshlib.protocol.SshMsgKexEcdhInit
import org.connectbot.sshlib.protocol.SshMsgKexEcdhReply
import org.connectbot.sshlib.protocol.SshMsgKexinit
import org.connectbot.sshlib.protocol.SshMsgPing
import org.connectbot.sshlib.protocol.SshMsgPong
import org.connectbot.sshlib.protocol.SshMsgServiceAccept
import org.connectbot.sshlib.protocol.SshMsgServiceRequest
import org.connectbot.sshlib.protocol.SshMsgUnimplemented
import org.connectbot.sshlib.protocol.SshMsgUserauthBanner
import org.connectbot.sshlib.protocol.SshMsgUserauthFailure
import org.connectbot.sshlib.protocol.SshMsgUserauthInfoRequest
import org.connectbot.sshlib.protocol.SshMsgUserauthPkOk
import org.connectbot.sshlib.protocol.SshMsgUserauthRequest
import org.connectbot.sshlib.protocol.SshMsgUserauthSuccess
import org.connectbot.sshlib.protocol.createAsciiString
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.createNameList
import org.connectbot.sshlib.protocol.createUtf8String
import org.connectbot.sshlib.protocol.toByteArray
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.PipedTransport
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

class FakeSshServer(
    private val serverTransport: PipedTransport,
    private val scope: CoroutineScope,
    private val coroutineContext: CoroutineContext = EmptyCoroutineContext,
) {
    private val _rekeyCount = MutableStateFlow(0)
    val rekeyCount: StateFlow<Int> = _rekeyCount.asStateFlow()

    private val hostKeyPair: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val hostKeyBlob: ByteArray = SshPublicKeyEncoder.encode(hostKeyPair.public, "ssh-ed25519")
    val serverHostKeyBlob: ByteArray
        get() = hostKeyBlob.copyOf()

    private lateinit var serverIo: PacketIO
    private lateinit var clientVersionStr: String
    private val serverVersionStr = "SSH-2.0-FakeServer_1.0"
    private val writeMutex = Mutex()

    private var sessionId: ByteArray? = null
    private var latestSharedSecret: ByteArray? = null
    private var latestExchangeHash: ByteArray? = null

    private val rekeyRequestChannel = Channel<Unit>(Channel.UNLIMITED)

    var advertisePing: Boolean = false
    var advertiseExtInfo: Boolean = false
    var kexAlgorithms: String? = null
    var corruptKexSignature: Boolean = false
    var sendDuplicateKexInitDuringRekey: Boolean = false
    private val receivedPongs = Channel<ByteArray>(Channel.UNLIMITED)
    private val receivedExtInfo = Channel<SshMsgExtInfo>(Channel.UNLIMITED)
    private val receivedUserauthRequests = Channel<SshMsgUserauthRequest>(Channel.UNLIMITED)
    private val receivedClientKexInits = Channel<SshMsgKexinit>(Channel.UNLIMITED)
    private val receivedChannelOpens = Channel<SshMsgChannelOpen>(Channel.UNLIMITED)
    private val receivedChannelRequests = Channel<SshMsgChannelRequest>(Channel.UNLIMITED)
    private val receivedChannelOpenConfirmations = Channel<SshMsgChannelOpenConfirmation>(Channel.UNLIMITED)
    private val receivedChannelOpenFailures = Channel<SshMsgChannelOpenFailure>(Channel.UNLIMITED)
    private val receivedChannelData = Channel<SshMsgChannelData>(Channel.UNLIMITED)
    private val receivedUnimplemented = Channel<SshMsgUnimplemented>(Channel.UNLIMITED)

    fun start(ignoreTransportErrors: Boolean = false) {
        scope.launch(coroutineContext) {
            if (ignoreTransportErrors) {
                runCatching { serve() }
            } else {
                serve()
            }
        }
    }

    /**
     * Request that the server initiate a re-key. The re-key will happen when
     * the server receives the next packet from the client (or when sendIgnore is called).
     */
    fun initiateRekey() {
        rekeyRequestChannel.trySend(Unit)
    }

    fun sendIgnore() {
        scope.launch(coroutineContext) {
            val msg = SshMsgIgnore().apply {
                setData(createByteString(byteArrayOf()))
                _check()
            }
            writeMutex.withLock {
                serverIo.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), msg.toByteArray())
            }
        }
    }

    private suspend fun serve() {
        serverIo = PacketIO(serverTransport)

        serverIo.writeBanner(serverVersionStr)
        val clientBanner = serverIo.readBanner()
        clientVersionStr = "SSH-" + clientBanner.protoVersion().trimEnd('\r', '\n')

        // Initial KEX: reads directly from serverIo (no reader coroutine yet)
        doFullKex(serverIo)
        sendExtInfo(serverIo)

        // After initial KEX, the client MAY send SSH_MSG_EXT_INFO,
        // followed by a SERVICE_REQUEST (ssh-userauth).
        var serviceRequest: ByteArray? = null
        while (serviceRequest == null) {
            val (msgType, rawBytes) = readPacketWithType(serverIo)
            when (msgType) {
                SshEnums.MessageType.SSH_MSG_EXT_INFO -> {
                    val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                    val extMsg = SshMsgExtInfo(ByteBufferKaitaiStream(bodyBytes))
                    extMsg._read()
                    receivedExtInfo.trySend(extMsg)
                }

                SshEnums.MessageType.SSH_MSG_SERVICE_REQUEST -> {
                    serviceRequest = rawBytes
                }

                SshEnums.MessageType.SSH_MSG_DEBUG,
                SshEnums.MessageType.SSH_MSG_IGNORE,
                -> { /* skip */ }

                else -> throw IllegalStateException("Unexpected packet during handshake: $msgType")
            }
        }
        sendServiceAccept(serverIo)

        // After authentication, all packets are routed through this channel by the reader
        // coroutine. This ensures there is only one concurrent reader of serverIo at all
        // times, even during re-key.
        val incomingPackets = Channel<Pair<SshEnums.MessageType, ByteArray>>(Channel.UNLIMITED)
        val readerJob = scope.launch {
            try {
                while (true) {
                    val packet = readPacketWithType(serverIo)
                    if (packet.first == SshEnums.MessageType.SSH_MSG_NEWKEYS) {
                        activateEncryption(serverIo)
                    }
                    incomingPackets.send(packet)
                }
            } catch (_: Exception) {
                incomingPackets.close()
            }
        }

        // Main loop
        while (true) {
            val done = select {
                rekeyRequestChannel.onReceive {
                    // Server-initiated rekey: send KEXINIT to client now; read from incomingPackets
                    doServerInitiatedKex(serverIo, incomingPackets)
                    false
                }
                incomingPackets.onReceiveCatching { result ->
                    val (msgType, rawBytes) = result.getOrNull() ?: return@onReceiveCatching true
                    when (msgType) {
                        SshEnums.MessageType.SSH_MSG_KEXINIT ->
                            doClientInitiatedKex(serverIo, rawBytes, incomingPackets)

                        SshEnums.MessageType.SSH_MSG_DISCONNECT -> return@onReceiveCatching true

                        SshEnums.MessageType.SSH_MSG_EXT_INFO -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val extMsg = SshMsgExtInfo(ByteBufferKaitaiStream(bodyBytes))
                            extMsg._read()
                            receivedExtInfo.trySend(extMsg)
                        }

                        SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val request = SshMsgUserauthRequest(ByteBufferKaitaiStream(bodyBytes))
                            request._read()
                            receivedUserauthRequests.trySend(request)
                        }

                        SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val request = SshMsgChannelOpen(ByteBufferKaitaiStream(bodyBytes))
                            request._read()
                            receivedChannelOpens.trySend(request)
                        }

                        SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val request = SshMsgChannelRequest(ByteBufferKaitaiStream(bodyBytes))
                            request._read()
                            receivedChannelRequests.trySend(request)
                        }

                        SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val confirmation = SshMsgChannelOpenConfirmation(ByteBufferKaitaiStream(bodyBytes))
                            confirmation._read()
                            receivedChannelOpenConfirmations.trySend(confirmation)
                        }

                        SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val failure = SshMsgChannelOpenFailure(ByteBufferKaitaiStream(bodyBytes))
                            failure._read()
                            receivedChannelOpenFailures.trySend(failure)
                        }

                        SshEnums.MessageType.SSH_MSG_CHANNEL_DATA -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val data = SshMsgChannelData(ByteBufferKaitaiStream(bodyBytes))
                            data._read()
                            receivedChannelData.trySend(data)
                        }

                        SshEnums.MessageType.SSH_MSG_PING -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val pingMsg = SshMsgPing(ByteBufferKaitaiStream(bodyBytes))
                            pingMsg._read()
                            val pong = SshMsgPong()
                            pong.setData(createByteString(pingMsg.data().data()))
                            pong._check()
                            writeMutex.withLock {
                                serverIo.writePacket(SshEnums.MessageType.SSH_MSG_PONG.id().toInt(), pong.toByteArray())
                            }
                        }

                        SshEnums.MessageType.SSH_MSG_PONG -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val pongMsg = SshMsgPong(ByteBufferKaitaiStream(bodyBytes))
                            pongMsg._read()
                            receivedPongs.trySend(pongMsg.data().data())
                        }

                        SshEnums.MessageType.SSH_MSG_UNIMPLEMENTED -> {
                            val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                            val unimplemented = SshMsgUnimplemented(ByteBufferKaitaiStream(bodyBytes))
                            unimplemented._read()
                            receivedUnimplemented.trySend(unimplemented)
                        }

                        else -> { /* ignore */ }
                    }
                    false
                }
            }
            if (done) break
        }
        readerJob.cancel()
    }

    private suspend fun doFullKex(io: PacketIO) {
        val serverKexInitBytes = sendKexInit(io)
        val clientKexInitRaw = readPacketRaw(io)
        val clientKexInit = SshMsgKexinit(ByteBufferKaitaiStream(clientKexInitRaw.copyOfRange(1, clientKexInitRaw.size)))
        clientKexInit._read()
        receivedClientKexInits.trySend(clientKexInit)
        val ecdhInitRaw = readPacketRaw(io)
        val clientPublic = parseEcdhInit(ecdhInitRaw)
        sendEcdhReply(io, clientKexInitRaw, serverKexInitBytes, clientPublic)
        writeMutex.withLock { io.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt()) }
        readPacketFiltering(io) // client NEWKEYS
        activateEncryption(io)
    }

    private suspend fun doServerInitiatedKex(
        io: PacketIO,
        packets: Channel<Pair<SshEnums.MessageType, ByteArray>>,
    ) {
        val serverKexInitBytes = sendKexInit(io)
        // After sending KEXINIT, wait for the client to send its KEXINIT
        val (firstType, firstRaw) = packets.receive()
        val clientKexInitRaw = if (firstType == SshEnums.MessageType.SSH_MSG_KEXINIT) {
            firstRaw
        } else {
            // Discard non-kexinit messages until we get KEXINIT
            var raw = firstRaw
            var type = firstType
            while (type != SshEnums.MessageType.SSH_MSG_KEXINIT) {
                val (t, r) = packets.receive()
                type = t
                raw = r
            }
            raw
        }
        if (sendDuplicateKexInitDuringRekey) {
            sendDuplicateKexInitDuringRekey = false
            sendKexInit(io)
            return
        }
        val (_, ecdhInitRaw) = packets.receive() // ECDH_INIT
        val clientPublic = parseEcdhInit(ecdhInitRaw)
        sendEcdhReply(io, clientKexInitRaw, serverKexInitBytes, clientPublic)
        writeMutex.withLock { io.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt()) }
        packets.receive() // client NEWKEYS (encryption already activated by reader)
        _rekeyCount.update { it + 1 }
    }

    private suspend fun doClientInitiatedKex(
        io: PacketIO,
        clientKexInitRaw: ByteArray,
        packets: Channel<Pair<SshEnums.MessageType, ByteArray>>,
    ) {
        val serverKexInitBytes = sendKexInit(io)
        val (_, ecdhInitRaw) = packets.receive() // ECDH_INIT
        val clientPublic = parseEcdhInit(ecdhInitRaw)
        sendEcdhReply(io, clientKexInitRaw, serverKexInitBytes, clientPublic)
        writeMutex.withLock { io.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt()) }
        packets.receive() // client NEWKEYS (encryption already activated by reader)
        _rekeyCount.update { it + 1 }
    }

    private suspend fun sendKexInit(io: PacketIO): ByteArray {
        val cookie = ByteArray(16).also { SecureRandom().nextBytes(it) }

        val kexAlgs = kexAlgorithms ?: if (advertiseExtInfo) {
            "curve25519-sha256,ext-info-s"
        } else {
            "curve25519-sha256"
        }

        val kexInit = SshMsgKexinit().apply {
            setCookie(cookie)
            setKexAlgorithms(createNameList(kexAlgs))
            setServerHostKeyAlgorithms(createNameList("ssh-ed25519"))
            setEncryptionAlgorithmsClientToServer(createNameList("aes128-ctr"))
            setEncryptionAlgorithmsServerToClient(createNameList("aes128-ctr"))
            setMacAlgorithmsClientToServer(createNameList("hmac-sha2-256-etm@openssh.com"))
            setMacAlgorithmsServerToClient(createNameList("hmac-sha2-256-etm@openssh.com"))
            setCompressionAlgorithmsClientToServer(createNameList("none"))
            setCompressionAlgorithmsServerToClient(createNameList("none"))
            setLanguagesClientToServer(createNameList(""))
            setLanguagesServerToClient(createNameList(""))
            setFirstKexPacketFollows(0)
            setReserved(0)
            _check()
        }

        val payload = kexInit.toByteArray()
        val rawBytes = byteArrayOf(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toByte()) + payload
        writeMutex.withLock { io.writePacket(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toInt(), payload) }
        return rawBytes
    }

    private suspend fun sendEcdhReply(
        io: PacketIO,
        clientKexInitRaw: ByteArray,
        serverKexInitBytes: ByteArray,
        clientPublic: ByteArray,
    ) {
        val x25519 = X25519ProviderFactory.provider
        val serverPrivate = x25519.generatePrivateKey()
        val serverPublic = x25519.publicFromPrivate(serverPrivate)

        val sharedSecretRaw = x25519.computeSharedSecret(serverPrivate, clientPublic)
        val sharedSecret = encodeMpint(BigInteger(1, sharedSecretRaw).toByteArray())

        val exchangeHash = computeExchangeHash(
            clientVersion = clientVersionStr.toByteArray(Charsets.US_ASCII),
            serverVersion = serverVersionStr.toByteArray(Charsets.US_ASCII),
            clientKexInit = clientKexInitRaw,
            serverKexInit = serverKexInitBytes,
            serverHostKey = hostKeyBlob,
            clientPublicKey = clientPublic,
            serverPublicKey = serverPublic,
            sharedSecret = sharedSecret,
        )

        latestSharedSecret = sharedSecret
        latestExchangeHash = exchangeHash
        if (sessionId == null) {
            sessionId = exchangeHash
        }

        val signature = signExchangeHash(exchangeHash).also {
            if (corruptKexSignature) it[0] = (it[0].toInt() xor 1).toByte()
        }
        val signatureBlob = buildSignatureBlob(signature)

        val reply = SshMsgKexEcdhReply().apply {
            setKS(createByteString(hostKeyBlob))
            setQS(createByteString(serverPublic))
            setSignatureH(createByteString(signatureBlob))
            _check()
        }

        writeMutex.withLock { io.writePacket(SshEnums.KexEcdh.SSH_MSG_KEX_ECDH_REPLY.id().toInt(), reply.toByteArray()) }
    }

    private fun activateEncryption(io: PacketIO) {
        val sharedSecret = latestSharedSecret ?: return
        val exchangeHash = latestExchangeHash ?: return
        val sid = sessionId ?: return

        val keyDerivation = KeyDerivation(sharedSecret, exchangeHash, sid, "SHA-256")
        val cipherEntry = CipherEntry.fromSshName("aes128-ctr") ?: return
        val macEntry = MacEntry.fromSshName("hmac-sha2-256-etm@openssh.com") ?: return

        val keys = keyDerivation.deriveKeys(
            ivLength = cipherEntry.ivLength,
            keyLength = cipherEntry.keyLength,
            macKeyLength = macEntry.keyLength,
        )

        val c2sKey = keys.encryptionKeyClientToServer.copyOf(cipherEntry.keyLength)
        val s2cKey = keys.encryptionKeyServerToClient.copyOf(cipherEntry.keyLength)
        val c2sIv = keys.initialIvClientToServer.copyOf(cipherEntry.ivLength)
        val s2cIv = keys.initialIvServerToClient.copyOf(cipherEntry.ivLength)

        // Server RECEIVES with C2S key (client encrypts, server decrypts with decrypt=false)
        val receiveCipher = (cipherEntry.create(c2sKey, c2sIv, false) as EncryptionInstance.Cipher).cipher
        // Server SENDS with S2C key (server encrypts, client decrypts)
        val sendCipher = (cipherEntry.create(s2cKey, s2cIv, true) as EncryptionInstance.Cipher).cipher

        val receiveMac = macEntry.create(keys.integrityKeyClientToServer)
        val sendMac = macEntry.create(keys.integrityKeyServerToClient)

        // PacketIO.enableEncryption parameters (from client perspective):
        //   clientToServerCipher -> PacketIO.sendCipher
        //   serverToClientCipher -> PacketIO.receiveCipher
        // For server: pass sendCipher as clientToServer, receiveCipher as serverToClient
        io.enableEncryption(
            clientToServerCipher = sendCipher,
            clientToServerMac = sendMac,
            serverToClientCipher = receiveCipher,
            serverToClientMac = receiveMac,
            clientToServerEtm = true,
            serverToClientEtm = true,
        )
    }

    private fun computeExchangeHash(
        clientVersion: ByteArray,
        serverVersion: ByteArray,
        clientKexInit: ByteArray,
        serverKexInit: ByteArray,
        serverHostKey: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray,
        sharedSecret: ByteArray,
    ): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArrayOutputStream()

        fun writeString(data: ByteArray) {
            val len = data.size
            buf.write(ByteBuffer.allocate(4).putInt(len).array())
            buf.write(data)
        }

        writeString(clientVersion)
        writeString(serverVersion)
        writeString(clientKexInit)
        writeString(serverKexInit)
        writeString(serverHostKey)
        writeString(clientPublicKey)
        writeString(serverPublicKey)
        buf.write(sharedSecret)

        return md.digest(buf.toByteArray())
    }

    private fun signExchangeHash(hash: ByteArray): ByteArray {
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(hostKeyPair.private)
        signer.update(hash)
        return signer.sign()
    }

    private fun buildSignatureBlob(signature: ByteArray): ByteArray {
        val algBytes = "ssh-ed25519".toByteArray(Charsets.US_ASCII)
        val out = ByteArrayOutputStream()
        out.write(ByteBuffer.allocate(4).putInt(algBytes.size).array())
        out.write(algBytes)
        out.write(ByteBuffer.allocate(4).putInt(signature.size).array())
        out.write(signature)
        return out.toByteArray()
    }

    suspend fun sendCustomExtInfo(extensions: Map<String, ByteArray>) {
        val msg = SshMsgExtInfo()
        msg.setNumExtensions(extensions.size.toLong())
        val extList = extensions.map { (name, value) ->
            SshMsgExtInfo.Extension().apply {
                set_root(msg)
                set_parent(msg)
                setExtensionName(createAsciiString(name))
                setExtensionValue(createByteString(value))
                _check()
            }
        }
        msg.setExtensions(ArrayList(extList))
        msg._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_EXT_INFO.id().toInt(), msg.toByteArray())
        }
    }

    private suspend fun sendExtInfo(io: PacketIO) {
        if (!advertiseExtInfo || !advertisePing) return
        val msg = SshMsgExtInfo()
        msg.setNumExtensions(1L)
        val ext = SshMsgExtInfo.Extension()
        ext.set_root(msg)
        ext.set_parent(msg)
        ext.setExtensionName(createAsciiString("ping@openssh.com"))
        ext.setExtensionValue(createByteString("0".toByteArray(Charsets.US_ASCII)))
        ext._check()
        msg.setExtensions(arrayListOf(ext))
        msg._check()
        writeMutex.withLock {
            io.writePacket(SshEnums.MessageType.SSH_MSG_EXT_INFO.id().toInt(), msg.toByteArray())
        }
    }

    private suspend fun sendServiceAccept(io: PacketIO) {
        val msg = SshMsgServiceAccept().apply {
            setServiceName(createAsciiString("ssh-userauth"))
            _check()
        }
        io.writePacket(SshEnums.MessageType.SSH_MSG_SERVICE_ACCEPT.id().toInt(), msg.toByteArray())
    }

    private suspend fun readPacketRaw(io: PacketIO): ByteArray {
        val packet = io.readPacket()
        return byteArrayOf(packet.messageType().id().toByte()) + packet._raw_body()
    }

    private suspend fun readPacketFiltering(io: PacketIO): Pair<SshEnums.MessageType, ByteArray> {
        while (true) {
            val packet = io.readPacket()
            val msgType = packet.messageType()
            val rawBytes = byteArrayOf(msgType.id().toByte()) + packet._raw_body()
            when (msgType) {
                SshEnums.MessageType.SSH_MSG_EXT_INFO -> {
                    val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
                    val extMsg = SshMsgExtInfo(ByteBufferKaitaiStream(bodyBytes))
                    extMsg._read()
                    receivedExtInfo.trySend(extMsg)
                }

                SshEnums.MessageType.SSH_MSG_DEBUG,
                SshEnums.MessageType.SSH_MSG_IGNORE,
                -> { /* skip */ }

                else -> return msgType to rawBytes
            }
        }
    }

    private suspend fun readPacketWithType(io: PacketIO): Pair<SshEnums.MessageType, ByteArray> {
        val packet = io.readPacket()
        val msgType = packet.messageType()
        val rawBytes = byteArrayOf(msgType.id().toByte()) + packet._raw_body()
        return msgType to rawBytes
    }

    private fun parseEcdhInit(rawBytes: ByteArray): ByteArray {
        val bodyBytes = rawBytes.copyOfRange(1, rawBytes.size)
        val stream = ByteBufferKaitaiStream(bodyBytes)
        val msg = SshMsgKexEcdhInit(stream)
        msg._read()
        return msg.qC().data()
    }

    fun sendServerPing(data: ByteArray) {
        scope.launch(coroutineContext) {
            val ping = SshMsgPing()
            ping.setData(createByteString(data))
            ping._check()
            writeMutex.withLock {
                serverIo.writePacket(SshEnums.MessageType.SSH_MSG_PING.id().toInt(), ping.toByteArray())
            }
        }
    }

    suspend fun sendServerPong(data: ByteArray) {
        val pong = SshMsgPong()
        pong.setData(createByteString(data))
        pong._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_PONG.id().toInt(), pong.toByteArray())
        }
    }

    suspend fun sendUnexpectedServiceRequest(service: String = "ssh-userauth") {
        val request = SshMsgServiceRequest().apply {
            setServiceName(createAsciiString(service))
            _check()
        }
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_SERVICE_REQUEST.id().toInt(), request.toByteArray())
        }
    }

    suspend fun sendUnknownPacket(messageNumber: Int = 191) {
        writeMutex.withLock {
            serverIo.writePacket(messageNumber, byteArrayOf())
        }
    }

    suspend fun awaitUnimplemented(): SshMsgUnimplemented = receivedUnimplemented.receive()

    suspend fun sendUserauthBanner(message: String) {
        val banner = SshMsgUserauthBanner()
        val utf8 = createUtf8String(message)
        banner.setMessage(utf8)
        banner.setLanguageTag(createByteString(ByteArray(0)))
        banner._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_USERAUTH_BANNER.id().toInt(), banner.toByteArray())
        }
    }

    suspend fun sendUserauthFailure(allowedMethods: Set<String>, partialSuccess: Boolean) {
        val failure = SshMsgUserauthFailure()
        failure.setValidAuthentications(createNameList(allowedMethods.joinToString(",")))
        failure.setPartialSuccess(if (partialSuccess) 1 else 0)
        failure._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_USERAUTH_FAILURE.id().toInt(), failure.toByteArray())
        }
    }

    suspend fun sendUserauthSuccess() {
        val success = SshMsgUserauthSuccess()
        success._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_USERAUTH_SUCCESS.id().toInt(), success.toByteArray())
        }
    }

    suspend fun sendUserauthPkOk(algorithmName: String, publicKeyBlob: ByteArray) {
        val pkOk = SshMsgUserauthPkOk()
        pkOk.setPublicKeyAlgorithmName(createAsciiString(algorithmName))
        pkOk.setPublicKeyBlob(createByteString(publicKeyBlob))
        pkOk._check()
        writeMutex.withLock {
            serverIo.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_60.id().toInt(),
                pkOk.toByteArray(),
            )
        }
    }

    suspend fun sendUserauthInfoRequest(
        name: String,
        instruction: String,
        prompts: List<Pair<String, Boolean>>,
    ) {
        val request = SshMsgUserauthInfoRequest()
        request.setName(createByteString(name.toByteArray(Charsets.UTF_8)))
        request.setInstruction(createByteString(instruction.toByteArray(Charsets.UTF_8)))
        request.setLanguageTag(createByteString(ByteArray(0)))
        request.setNumPrompts(prompts.size.toLong())
        val promptMessages = prompts.map { (prompt, echo) ->
            SshMsgUserauthInfoRequest.Prompt().apply {
                set_root(request)
                set_parent(request)
                setPrompt(createByteString(prompt.toByteArray(Charsets.UTF_8)))
                setEcho(if (echo) 1 else 0)
                _check()
            }
        }
        request.setPrompts(ArrayList(promptMessages))
        request._check()
        writeMutex.withLock {
            serverIo.writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_60.id().toInt(),
                request.toByteArray(),
            )
        }
    }

    suspend fun sendChannelOpenConfirmation(
        recipientChannel: Int,
        senderChannel: Int,
        initialWindowSize: Int = 64 * 1024,
        maximumPacketSize: Int = 32 * 1024,
    ) {
        val confirmation = SshMsgChannelOpenConfirmation()
        confirmation.setRecipientChannel(recipientChannel.toLong())
        confirmation.setSenderChannel(senderChannel.toLong())
        confirmation.setInitialWindowSize(initialWindowSize.toLong())
        confirmation.setMaximumPacketSize(maximumPacketSize.toLong())
        confirmation._check()
        writeMutex.withLock {
            serverIo.writePacket(
                SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.id().toInt(),
                confirmation.toByteArray(),
            )
        }
    }

    suspend fun sendChannelOpenFailure(recipientChannel: Int) {
        val failure = SshMsgChannelOpenFailure()
        failure.setRecipientChannel(recipientChannel.toLong())
        failure.setReasonCode(2)
        failure.setDescription(createByteString("open failed".toByteArray(Charsets.UTF_8)))
        failure.setLanguageTag(createByteString(ByteArray(0)))
        failure._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE.id().toInt(), failure.toByteArray())
        }
    }

    suspend fun sendChannelSuccess(recipientChannel: Int) {
        val success = SshMsgChannelSuccess()
        success.setRecipientChannel(recipientChannel.toLong())
        success._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_SUCCESS.id().toInt(), success.toByteArray())
        }
    }

    suspend fun sendChannelFailure(recipientChannel: Int) {
        val failure = SshMsgChannelFailure()
        failure.setRecipientChannel(recipientChannel.toLong())
        failure._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_FAILURE.id().toInt(), failure.toByteArray())
        }
    }

    suspend fun sendChannelData(recipientChannel: Int, data: ByteArray) {
        val payload = ByteArrayOutputStream()
        payload.write(ByteBuffer.allocate(4).putInt(recipientChannel).array())
        payload.writeString(data)
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_DATA.id().toInt(), payload.toByteArray())
        }
    }

    suspend fun sendChannelExtendedData(recipientChannel: Int, dataTypeCode: Int, data: ByteArray) {
        val payload = ByteArrayOutputStream()
        payload.write(ByteBuffer.allocate(4).putInt(recipientChannel).array())
        payload.write(ByteBuffer.allocate(4).putInt(dataTypeCode).array())
        payload.writeString(data)
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA.id().toInt(), payload.toByteArray())
        }
    }

    suspend fun sendChannelWindowAdjust(recipientChannel: Int, bytesToAdd: Long) {
        require(bytesToAdd in 0..0xFFFF_FFFFL) { "bytesToAdd must fit SSH uint32" }
        val payload = ByteBuffer.allocate(8)
            .putInt(recipientChannel)
            .putInt(bytesToAdd.toInt())
            .array()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST.id().toInt(), payload)
        }
    }

    suspend fun sendChannelEof(recipientChannel: Int) {
        val payload = ByteBuffer.allocate(4).putInt(recipientChannel).array()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_EOF.id().toInt(), payload)
        }
    }

    suspend fun sendChannelClose(recipientChannel: Int) {
        val payload = ByteBuffer.allocate(4).putInt(recipientChannel).array()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE.id().toInt(), payload)
        }
    }

    suspend fun sendRequestSuccess(payload: ByteArray = ByteArray(0)) {
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_REQUEST_SUCCESS.id().toInt(), payload)
        }
    }

    suspend fun sendRequestFailure() {
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_REQUEST_FAILURE.id().toInt())
        }
    }

    suspend fun sendDisconnect(description: String = "bye") {
        val msg = SshMsgDisconnect()
        msg.setReasonCode(SshEnums.DisconnectReason.SSH_DISCONNECT_BY_APPLICATION)
        msg.setDescription(createUtf8String(description))
        msg.setLanguage(createAsciiString(""))
        msg._check()
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_DISCONNECT.id().toInt(), msg.toByteArray())
        }
    }

    suspend fun sendGlobalRequest(requestName: String, wantReply: Boolean) {
        val payload = ByteArrayOutputStream()
        payload.writeString(requestName.toByteArray(Charsets.US_ASCII))
        payload.write(if (wantReply) 1 else 0)
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST.id().toInt(), payload.toByteArray())
        }
    }

    suspend fun sendChannelOpen(channelType: String, senderChannel: Int) {
        sendChannelOpenPacket(channelType, senderChannel, channelSpecificData = ByteArray(0))
    }

    suspend fun sendForwardedTcpipChannelOpen(
        senderChannel: Int,
        connectedAddress: String,
        connectedPort: Int,
        originatorAddress: String,
        originatorPort: Int,
    ) {
        val data = ByteArrayOutputStream()
        data.writeString(connectedAddress.toByteArray(Charsets.US_ASCII))
        data.write(ByteBuffer.allocate(4).putInt(connectedPort).array())
        data.writeString(originatorAddress.toByteArray(Charsets.US_ASCII))
        data.write(ByteBuffer.allocate(4).putInt(originatorPort).array())
        sendChannelOpenPacket("forwarded-tcpip", senderChannel, data.toByteArray())
    }

    private suspend fun sendChannelOpenPacket(channelType: String, senderChannel: Int, channelSpecificData: ByteArray) {
        val payload = ByteArrayOutputStream()
        payload.writeString(channelType.toByteArray(Charsets.US_ASCII))
        payload.write(ByteBuffer.allocate(4).putInt(senderChannel).array())
        payload.write(ByteBuffer.allocate(4).putInt(64 * 1024).array())
        payload.write(ByteBuffer.allocate(4).putInt(32 * 1024).array())
        payload.write(channelSpecificData)
        writeMutex.withLock {
            serverIo.writePacket(SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN.id().toInt(), payload.toByteArray())
        }
    }

    private fun ByteArrayOutputStream.writeString(data: ByteArray) {
        write(ByteBuffer.allocate(4).putInt(data.size).array())
        write(data)
    }

    suspend fun awaitPong(): ByteArray = receivedPongs.receive()

    suspend fun awaitExtInfo(): SshMsgExtInfo = receivedExtInfo.receive()

    suspend fun awaitUserauthRequest(): SshMsgUserauthRequest = receivedUserauthRequests.receive()

    suspend fun awaitClientKexInit(): SshMsgKexinit = receivedClientKexInits.receive()

    suspend fun awaitChannelOpen(): SshMsgChannelOpen = receivedChannelOpens.receive()

    suspend fun awaitChannelRequest(): SshMsgChannelRequest = receivedChannelRequests.receive()

    suspend fun awaitChannelOpenConfirmation(): SshMsgChannelOpenConfirmation = receivedChannelOpenConfirmations.receive()

    suspend fun awaitChannelOpenFailure(): SshMsgChannelOpenFailure = receivedChannelOpenFailures.receive()

    suspend fun awaitChannelData(): SshMsgChannelData = receivedChannelData.receive()
}
