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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CloseableCoroutineDispatcher
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.ConnectionInfo
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PingResult
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SessionExit
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
import org.connectbot.sshlib.crypto.PacketAead
import org.connectbot.sshlib.crypto.PacketCipher
import org.connectbot.sshlib.crypto.PacketCompressor
import org.connectbot.sshlib.crypto.PacketMac
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.crypto.SignatureVerifier
import org.connectbot.sshlib.crypto.SshPrivateKey
import org.connectbot.sshlib.crypto.SshPublicKeyEncoder
import org.connectbot.sshlib.kaitaiParseFailureOrNull
import org.connectbot.sshlib.protocol.AsciiString
import org.connectbot.sshlib.protocol.ChannelOpenDirectTcpip
import org.connectbot.sshlib.protocol.ChannelOpenForwardedTcpip
import org.connectbot.sshlib.protocol.ChannelOpenSession
import org.connectbot.sshlib.protocol.ChannelRequestExitSignal
import org.connectbot.sshlib.protocol.ChannelRequestExitStatus
import org.connectbot.sshlib.protocol.GlobalRequestCancelTcpipForward
import org.connectbot.sshlib.protocol.GlobalRequestResponseTcpipForward
import org.connectbot.sshlib.protocol.GlobalRequestTcpipForward
import org.connectbot.sshlib.protocol.IdBanner
import org.connectbot.sshlib.protocol.KexDhGexPayload
import org.connectbot.sshlib.protocol.KexEcdhPayload
import org.connectbot.sshlib.protocol.KexdhPayload
import org.connectbot.sshlib.protocol.SshChannelState
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import org.connectbot.sshlib.protocol.SshClientCallbacks
import org.connectbot.sshlib.protocol.SshClientStateMachine
import org.connectbot.sshlib.protocol.SshEnums
import org.connectbot.sshlib.protocol.SshMsgChannelClose
import org.connectbot.sshlib.protocol.SshMsgChannelData
import org.connectbot.sshlib.protocol.SshMsgChannelEof
import org.connectbot.sshlib.protocol.SshMsgChannelExtendedData
import org.connectbot.sshlib.protocol.SshMsgChannelFailure
import org.connectbot.sshlib.protocol.SshMsgChannelOpen
import org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation
import org.connectbot.sshlib.protocol.SshMsgChannelOpenFailure
import org.connectbot.sshlib.protocol.SshMsgChannelRequest
import org.connectbot.sshlib.protocol.SshMsgChannelSuccess
import org.connectbot.sshlib.protocol.SshMsgChannelWindowAdjust
import org.connectbot.sshlib.protocol.SshMsgDebug
import org.connectbot.sshlib.protocol.SshMsgDisconnect
import org.connectbot.sshlib.protocol.SshMsgExtInfo
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
import org.connectbot.sshlib.protocol.SshMsgPing
import org.connectbot.sshlib.protocol.SshMsgPong
import org.connectbot.sshlib.protocol.SshMsgServiceAccept
import org.connectbot.sshlib.protocol.SshMsgServiceRequest
import org.connectbot.sshlib.protocol.SshMsgUnimplemented
import org.connectbot.sshlib.protocol.SshMsgUserauthBanner
import org.connectbot.sshlib.protocol.SshMsgUserauthFailure
import org.connectbot.sshlib.protocol.SshMsgUserauthInfoRequest
import org.connectbot.sshlib.protocol.SshMsgUserauthInfoResponse
import org.connectbot.sshlib.protocol.SshMsgUserauthPkOk
import org.connectbot.sshlib.protocol.SshMsgUserauthRequest
import org.connectbot.sshlib.protocol.UnencryptedPacket
import org.connectbot.sshlib.protocol.UserauthPublickeyHostboundSignatureData
import org.connectbot.sshlib.protocol.UserauthPublickeySignatureData
import org.connectbot.sshlib.protocol.UserauthRequestKeyboardInteractive
import org.connectbot.sshlib.protocol.UserauthRequestNone
import org.connectbot.sshlib.protocol.UserauthRequestPassword
import org.connectbot.sshlib.protocol.UserauthRequestPublickey
import org.connectbot.sshlib.protocol.UserauthRequestPublickeyHostbound
import org.connectbot.sshlib.protocol.createAsciiString
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.createMpint
import org.connectbot.sshlib.protocol.createNameList
import org.connectbot.sshlib.protocol.createUtf8String
import org.connectbot.sshlib.protocol.toByteArray
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportException
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.CoroutineContext
import org.connectbot.sshlib.AuthResult as PublicAuthResult

internal fun boundRemotePacketSize(packetSize: Long): Int? = when {
    packetSize <= 0L -> null
    packetSize > 0xFFFFFFFFL -> null
    else -> minOf(packetSize, 32L * 1024L).toInt()
}

internal fun isKeyExchangeMessage(messageId: Int): Boolean = messageId == SshEnums.MessageType.SSH_MSG_KEXINIT.id().toInt() ||
    messageId == SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt() ||
    messageId in 30..49

private sealed interface PendingProtection {
    fun installOutbound(packetIO: PacketIO)
    fun installInbound(packetIO: PacketIO)
    fun destroy()
}

private class PendingAeadProtection(
    private var outbound: PacketAead?,
    private var inbound: PacketAead?,
) : PendingProtection {
    override fun installOutbound(packetIO: PacketIO) {
        val aead = outbound ?: throw SshException("Outbound AEAD protection already installed")
        packetIO.enableSendAead(aead)
        outbound = null
    }

    override fun installInbound(packetIO: PacketIO) {
        val aead = inbound ?: throw SshException("Inbound AEAD protection already installed")
        packetIO.enableReceiveAead(aead)
        inbound = null
    }

    override fun destroy() {
        outbound?.destroy()
        outbound = null
        inbound?.destroy()
        inbound = null
    }
}

private class PendingCipherProtection(
    private var outboundCipher: PacketCipher?,
    private var outboundMac: PacketMac?,
    private val outboundEtm: Boolean,
    private var inboundCipher: PacketCipher?,
    private var inboundMac: PacketMac?,
    private val inboundEtm: Boolean,
) : PendingProtection {
    override fun installOutbound(packetIO: PacketIO) {
        val cipher = outboundCipher ?: throw SshException("Outbound cipher protection already installed")
        val mac = outboundMac ?: throw SshException("Outbound MAC protection already installed")
        packetIO.enableSendEncryption(cipher, mac, outboundEtm)
        outboundCipher = null
        outboundMac = null
    }

    override fun installInbound(packetIO: PacketIO) {
        val cipher = inboundCipher ?: throw SshException("Inbound cipher protection already installed")
        val mac = inboundMac ?: throw SshException("Inbound MAC protection already installed")
        packetIO.enableReceiveEncryption(cipher, mac, inboundEtm)
        inboundCipher = null
        inboundMac = null
    }

    override fun destroy() {
        outboundCipher?.destroy()
        outboundCipher = null
        outboundMac?.destroy()
        outboundMac = null
        inboundCipher?.destroy()
        inboundCipher = null
        inboundMac?.destroy()
        inboundMac = null
    }
}

/**
 * SSH connection handler that manages the protocol flow.
 *
 * This class ties together the state machine, transport layer, and crypto
 * implementations to handle a complete SSH connection lifecycle.
 *
 * @param transport Underlying transport (e.g., TCP socket)
 * @param clientVersion Client version string (default: SSH-2.0-CBSSH_1.0)
 */
@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
class SshConnection(
    private val transport: Transport,
    private val clientVersion: String = "SSH-2.0-CBSSH_1.0",
    private val hostKeyVerifier: HostKeyVerifier,
    kexAlgorithms: String = KexEntry.defaultString,
    private val hostKeyAlgorithms: String = SignatureEntry.defaultString,
    private val encryptionAlgorithms: String = CipherEntry.defaultString,
    private val macAlgorithms: String = MacEntry.defaultString,
    private val compressionAlgorithms: String = CompressionEntry.defaultString,
    private val preferPasswordAuth: Boolean = false,
    private val rekeyIntervalMs: Long = 3_600_000L,
    private val rekeyBytesLimit: Long = 1_073_741_824L,
    private val obscureKeystrokeTimingIntervalMs: Long = 20L,
    coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    internal var autoDisconnectOnLastChannelClose: Boolean = true

    companion object {
        private val logger = LoggerFactory.getLogger(SshConnection::class.java)
        private const val KEX_EXT_INFO_C = "ext-info-c"
        private const val SERVICE_SSH_CONNECTION = "ssh-connection"
        private const val KEY_TYPE_SSH_RSA = "ssh-rsa"
        private const val METHOD_PUBLICKEY_HOSTBOUND = "publickey-hostbound-v00@openssh.com"
        private const val CHANNEL_FORWARDED_TCPIP = "forwarded-tcpip"
        private const val ERROR_SESSION_ID_NOT_ESTABLISHED = "Session ID not established"
        private const val ERROR_CLIENT_PUBLIC_KEY_NOT_GENERATED = "Client public key not generated"
        private const val ERROR_NO_KEX_ALGORITHM_INITIALIZED = "No KEX algorithm initialized"
        private const val SSH_MSG_USERAUTH_REQUEST_ID = 50
        private const val MAX_REKEY_IN_FLIGHT_PACKETS = 1_024

        private fun stripExtInfoC(kexAlgorithms: String): String = kexAlgorithms.split(",")
            .filter { it.isNotEmpty() && it != KEX_EXT_INFO_C }
            .joinToString(",")

        private fun appendExtInfoC(kexAlgorithms: String): String {
            val algorithms = kexAlgorithms.split(",").filter { it.isNotEmpty() }
            return if (KEX_EXT_INFO_C in algorithms) {
                kexAlgorithms
            } else {
                (algorithms + KEX_EXT_INFO_C).joinToString(",")
            }
        }

        private fun parseNameList(nameList: String): List<String> = nameList.split(",").filter { it.isNotEmpty() }
    }

    private val kexAlgorithms: String = stripExtInfoC(kexAlgorithms)
    private val initialKexAlgorithms: String = appendExtInfoC(this.kexAlgorithms)

    private val stateMachineDispatcher = coroutineDispatcher.limitedParallelism(1, "StateMachine")

    private class HostKeyRejectedException(val key: PublicKey) : Exception("Host key rejected")

    private class ProtocolViolationException(
        message: String,
        cause: Throwable? = null,
        val responseSent: Boolean = false,
    ) : SshException(message, cause)

    private val packetIO = PacketIO(transport)

    private val callbacks = object : SshClientCallbacks {
        override fun sendVersion() = this@SshConnection.sendVersion()
        override fun receiveVersion(banner: IdBanner) = this@SshConnection.receiveVersion(banner)
        override suspend fun sendKexInit() = this@SshConnection.sendKexInit()
        override fun receiveKexInit(msg: SshMsgKexinit, initialExchange: Boolean) = this@SshConnection.receiveKexInit(msg, initialExchange)
        override suspend fun sendKexExchangeInit() = this@SshConnection.sendKexExchangeInit()
        override suspend fun receiveKexDhReply(msg: SshMsgKexdhReply) = this@SshConnection.receiveKexDhReply(msg)
        override suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) = this@SshConnection.receiveKexEcdhReply(msg)
        override suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) = this@SshConnection.receiveKexDhGexReply(msg)
        override fun isRekeying(): Boolean = this@SshConnection.isRekeying
        override fun isAuthenticationRequestPending(): Boolean = this@SshConnection.authRequestPending
        override fun authenticationRequestStarted() {
            this@SshConnection.authRequestPending = true
        }
        override fun authenticationRequestResponseReceived() {
            this@SshConnection.authRequestPending = false
        }
        override fun rekeyStarted() = this@SshConnection.rekeyStarted()
        override fun rekeyComplete() = this@SshConnection.rekeyComplete()
        override suspend fun sendKexDhGexInit() = this@SshConnection.sendKexDhGexInit()
        override suspend fun sendNewKeys(resetSequenceNumber: Boolean) = this@SshConnection.sendNewKeys(resetSequenceNumber)
        override fun receiveNewKeys(resetSequenceNumber: Boolean) = this@SshConnection.receiveNewKeys(resetSequenceNumber)
        override fun activateEncryption() = this@SshConnection.activateEncryption()
        override suspend fun sendClientExtInfo() = this@SshConnection.sendClientExtInfo()
        override suspend fun sendServiceRequest(service: String) = this@SshConnection.sendServiceRequest(service)
        override fun receiveServiceAccept(service: String) = this@SshConnection.receiveServiceAccept(service)
        override fun startAuthentication() = this@SshConnection.startAuthentication()
        override fun authenticationSuccess() = this@SshConnection.authenticationSuccess()
        override fun authenticationFailure() = this@SshConnection.authenticationFailure()
        override fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest) = this@SshConnection.receiveUserauthInfoRequest(msg)
        override fun receiveUserauthBanner(msg: SshMsgUserauthBanner) = this@SshConnection.receiveUserauthBanner(msg)
        override suspend fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int) = this@SshConnection.sendChannelOpen(channelType, localChannelNumber, initialWindowSize, maxPacketSize)
        override suspend fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) = this@SshConnection.receiveChannelOpenConfirmation(msg)
        override suspend fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) = this@SshConnection.receiveChannelOpenFailure(msg)
        override suspend fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) = this@SshConnection.sendChannelRequest(recipientChannel, requestType, wantReply, message)
        override fun receiveChannelSuccess(recipientChannel: Int) = this@SshConnection.receiveChannelSuccess(recipientChannel)
        override fun receiveChannelFailure(recipientChannel: Int) = this@SshConnection.receiveChannelFailure(recipientChannel)
        override suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest) = this@SshConnection.receiveGlobalRequest(msg)
        override fun debug(msg: SshMsgDebug) = this@SshConnection.debug(msg)
        override fun ignore() = this@SshConnection.ignore()
        override suspend fun disconnect() = this@SshConnection.disconnect()
        override suspend fun sendProtocolError(description: String) = this@SshConnection.sendProtocolError(description)
        override fun onStateEnter(stateName: String) = this@SshConnection.onStateEnter(stateName)
        override fun onStateExit(stateName: String) = this@SshConnection.onStateExit(stateName)
    }

    private val stateMachine = SshClientStateMachine(callbacks)
    private val inboundPacketController = InboundPacketController()
    internal val connectionScope = CoroutineScope(SupervisorJob() + coroutineDispatcher)
    private val writeMutex = Mutex()
    private val outboundPacketController = OutboundPacketController()
    private var transportClosing = false

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
    private var negotiatedHostKeyAlgorithm: String? = null
    private var negotiatedEncryptionC2S: String? = null
    private var negotiatedEncryptionS2C: String? = null
    private var negotiatedMacC2S: String? = null
    private var negotiatedMacS2C: String? = null
    private var negotiatedCompressionC2S: String? = null
    private var negotiatedCompressionS2C: String? = null
    private var serverAdvertisesExtInfo: Boolean = false
    private var serverExtInfoReceivedCount: Int = 0
    private var clientExtInfoSent: Boolean = false

    private var nextLocalChannelNumber = 0
    private val channelNumberLock = Mutex()
    private val channelRegistry = SshChannelRegistry()

    private var agentProvider: AgentProvider? = null
    private var serverHostKeyBlob: ByteArray? = null

    @Volatile private var serverAdvertisesHostBound: Boolean = false

    @Volatile private var serverSigAlgs: Set<String>? = null

    @Volatile internal var serverSupportsPing: Boolean = false
    private val pingSequence = AtomicLong(0)
    private data class PendingPing(
        val deferred: CompletableDeferred<PingResult>,
        val payload: ByteArray,
        val sentTimeNs: Long? = null,
    )
    private val pendingPings = HashMap<Long, PendingPing>()
    private val pendingPingQueue = ArrayDeque<suspend () -> Unit>()

    /**
     * Helper to manage a pending asynchronous operation that waits for a server response.
     * Ensures all state changes happen on the [stateMachineDispatcher].
     */
    private inner class PendingValue<T> {
        @Volatile
        private var deferred: CompletableDeferred<T>? = null

        suspend fun set(value: CompletableDeferred<T>) {
            withContext(stateMachineDispatcher) {
                check(deferred == null) { "Operation already has a pending reply" }
                deferred = value
            }
        }

        /**
         * Set the deferred directly. Must only be called from within [stateMachineDispatcher].
         */
        fun setDirect(value: CompletableDeferred<T>) {
            check(deferred == null) { "Operation already has a pending reply" }
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
    private val pendingChannelRequests = HashMap<Int, CompletableDeferred<Boolean>>()
    private val pendingGlobalRequest = PendingValue<ByteArray?>()

    private val remoteForwarders = ConcurrentHashMap<String, suspend (connectedAddr: String, connectedPort: Int, originAddr: String, originPort: Int, senderChannel: Int, initialWindow: Long, maxPacketSize: Int) -> Unit>()

    private var infoRequestChannel: Channel<SshMsgUserauthInfoRequest>? = null

    // Strategy-based authentication state
    @Volatile private var authResultChannel: Channel<InternalAuthResult>? = null

    @Volatile private var allowedAuthentications: Set<String>? = null

    @Volatile private var currentAuthMethod: AuthMethod? = null
    private val triedPublicKeys: MutableSet<AuthPublicKey> = Collections.synchronizedSet(mutableSetOf())

    private var packetLoopJob: Job? = null

    @Volatile internal var isRekeying = false

    @Volatile private var authRequestPending = false

    private var rekeyTimerJob: Job? = null

    @Volatile private var pendingConnect: CompletableDeferred<ConnectResult>? = null
    private var dhGexGroup: SshMsgKexDhGexGroup? = null
    private var pendingProtection: PendingProtection? = null
    private var pendingSendCompressor: PacketCompressor? = null
    private var pendingReceiveCompressor: PacketCompressor? = null
    private var pendingCompressionImmediate = false

    private suspend fun dispatchCommand(name: String, command: suspend SshClientStateMachine.() -> Boolean) {
        logger.debug("Dispatching command: $name")
        try {
            withContext(stateMachineDispatcher) {
                check(stateMachine.command()) { "Command $name is not valid in the current SSH state" }
            }
        } catch (e: Exception) {
            logger.error("State machine failed to process command: $name", e)
            throw e
        }
    }

    /** Serialized write to the transport, subject to the RFC 4253 key-exchange gate. */
    private suspend fun writePacket(messageType: Int, payload: ByteArray = byteArrayOf()) {
        outboundPacketController.writePacket(messageType, payload)
    }

    private inner class OutboundPacketController {
        @Volatile
        private var kexCompletion = CompletableDeferred(Unit)

        fun beginKex() {
            check(kexCompletion.isCompleted) { "Key exchange is already in progress" }
            kexCompletion = CompletableDeferred()
        }

        fun completeKex() {
            kexCompletion.complete(Unit)
        }

        suspend fun writePacket(
            messageType: Int,
            payload: ByteArray = byteArrayOf(),
            beforeWrite: () -> Unit = {},
            afterWrite: () -> Unit = {},
        ) {
            while (true) {
                val observedKex = kexCompletion
                if (!isAllowedDuringKex(messageType)) {
                    observedKex.await()
                }

                var written = false
                writeMutex.withLock {
                    checkTransportOpen()
                    if (isAllowedDuringKex(messageType) || kexCompletion.isCompleted) {
                        beforeWrite()
                        packetIO.writePacket(messageType, payload)
                        afterWrite()
                        written = true
                    }
                }
                if (written) return
            }
        }

        private fun isAllowedDuringKex(messageType: Int): Boolean = messageType in 1..4 || messageType in 7..49
    }

    private fun checkTransportOpen() {
        if (transportClosing) {
            throw TransportException("Transport is closed")
        }
    }

    /** Prevent new writes before closing the underlying transport exactly once. */
    private suspend fun closeTransport() {
        withContext(NonCancellable) {
            writeMutex.withLock {
                if (transportClosing) return@withLock
                transportClosing = true
                try {
                    transport.close()
                } finally {
                    outboundPacketController.completeKex()
                }
            }
        }
    }

    /**
     * Initiate SSH connection.
     * Performs SSH version exchange, key exchange, and service negotiation.
     * Returns [ConnectResult.Success] when the transport is ready for authentication calls.
     */
    suspend fun connect(): ConnectResult {
        val deferred = CompletableDeferred<ConnectResult>()
        pendingConnect = deferred

        return try {
            dispatchCommand("Connect") { connect() }

            // Version exchange — text protocol, handled inline
            packetIO.writeBanner(clientVersion)
            val banner = packetIO.readBanner()
            dispatchCommand("ReceiveVersion") { receiveVersion(banner) }

            // Start packet loop — handles all binary SSH packets from here
            startPacketLoop()

            withTimeout(30_000L) { deferred.await() }
        } catch (e: TimeoutCancellationException) {
            ConnectResult.TransportError(Exception("Connection timed out"))
        } catch (e: HostKeyRejectedException) {
            ConnectResult.HostKeyRejected(e.key)
        } catch (e: SshException) {
            when {
                e.message?.startsWith("No matching") == true ||
                    e.message?.startsWith("No KEX") == true ||
                    e.message?.startsWith("Unknown KEX") == true ->
                    ConnectResult.AlgorithmMismatch(e.message ?: "Algorithm mismatch")

                e.message?.contains("host key", ignoreCase = true) == true ->
                    ConnectResult.ProtocolError(e.message ?: "Host key error", e)

                else -> ConnectResult.ProtocolError(e.message ?: "Protocol error", e)
            }
        } catch (e: Exception) {
            ConnectResult.TransportError(e)
        } finally {
            pendingConnect = null
        }
    }

    /**
     * Authenticate using password.
     *
     * @param username Username
     * @param password Password
     */
    suspend fun authenticatePassword(username: String, password: String): PublicAuthResult {
        try {
            val req = SshMsgUserauthRequest().apply {
                setUserName(createAsciiString(username))
                setServiceName(createAsciiString(SERVICE_SSH_CONNECTION))
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
            dispatchCommand("BeginPasswordAuthentication") { beginAuthentication() }
            pendingAuth.set(deferred)

            writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray(),
            )

            try {
                val success = deferred.await()
                return if (success) {
                    PublicAuthResult.Success
                } else {
                    PublicAuthResult.Failure(allowedAuthentications ?: emptySet())
                }
            } finally {
                pendingAuth.clearIfSame(deferred)
            }
        } catch (e: Exception) {
            logger.error("Authentication error", e)
            return PublicAuthResult.Error(e.message ?: "Authentication error", e)
        }
    }

    /**
     * Authenticate using keyboard-interactive (RFC 4256).
     *
     * @param username Username
     * @param callback Callback that receives prompts and provides responses
     */
    suspend fun authenticateKeyboardInteractive(
        username: String,
        callback: KeyboardInteractiveCallback,
    ): PublicAuthResult {
        try {
            val req = SshMsgUserauthRequest().apply {
                setUserName(createAsciiString(username))
                setServiceName(createAsciiString(SERVICE_SSH_CONNECTION))
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
            dispatchCommand("BeginKeyboardInteractiveAuthentication") { beginAuthentication() }
            pendingAuth.set(deferred)
            withContext(stateMachineDispatcher) {
                infoRequestChannel = channel
            }

            writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray(),
            )

            val consumerJob = connectionScope.launch {
                for (infoRequest in channel) {
                    val name = String(infoRequest.name().data(), Charsets.UTF_8)
                    val instruction = String(infoRequest.instruction().data(), Charsets.UTF_8)
                    val prompts = infoRequest.prompts().map { prompt ->
                        KeyboardInteractiveCallback.Prompt(
                            text = String(prompt.prompt().data(), Charsets.UTF_8),
                            echo = prompt.echo() != 0,
                        )
                    }

                    callback.onInfoRequest(name, instruction, prompts) { responses ->
                        val responseMsg = SshMsgUserauthInfoResponse().apply {
                            setNumResponses(responses.size.toLong())
                            setResponses(
                                responses.map { response ->
                                    val bytes = response.toByteArray(Charsets.UTF_8)
                                    createByteString(bytes)
                                },
                            )
                            _check()
                        }

                        writePacket(
                            SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_61.id().toInt(),
                            responseMsg.toByteArray(),
                        )
                    }
                }
            }

            try {
                val success = deferred.await()
                return if (success) {
                    PublicAuthResult.Success
                } else {
                    PublicAuthResult.Failure(allowedAuthentications ?: emptySet())
                }
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
            return PublicAuthResult.Error(e.message ?: "Keyboard-interactive error", e)
        }
    }

    /**
     * Authenticate using public key (RFC 4252 §7).
     *
     * @param username Username
     * @param privateKey Parsed private key
     */
    internal suspend fun authenticatePublicKey(username: String, privateKey: SshPrivateKey): PublicAuthResult {
        try {
            val sid = sessionId ?: throw SshException(ERROR_SESSION_ID_NOT_ESTABLISHED)

            val publicKeyBlob = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)

            val sigAlgorithmName = if (privateKey.keyType == KEY_TYPE_SSH_RSA) {
                negotiateRsaAlgorithm()
                    ?: return PublicAuthResult.Failure(allowedAuthentications ?: setOf("publickey"))
            } else {
                privateKey.signatureAlgorithm
            }
            val sigEntry = SignatureEntry.fromSshName(sigAlgorithmName)
                ?: throw SshException("Unknown signature algorithm: $sigAlgorithmName")

            val hostBoundKeyBlob = serverHostKeyBlob.takeIf { serverAdvertisesHostBound }

            val signatureData = if (hostBoundKeyBlob != null) {
                buildHostBoundSignatureData(sid, username, SERVICE_SSH_CONNECTION, sigAlgorithmName, publicKeyBlob, hostBoundKeyBlob)
            } else {
                buildSignatureData(sid, username, SERVICE_SSH_CONNECTION, sigAlgorithmName, publicKeyBlob)
            }

            val signature = sigEntry.algorithm.sign(
                sigAlgorithmName,
                privateKey.jcaKeyPair.private,
                signatureData,
            )

            val req = SshMsgUserauthRequest().apply {
                setUserName(createAsciiString(username))
                setServiceName(createAsciiString(SERVICE_SSH_CONNECTION))

                if (hostBoundKeyBlob != null) {
                    setMethodName(createAsciiString(METHOD_PUBLICKEY_HOSTBOUND))
                    val pubkeyAuth = UserauthRequestPublickeyHostbound().apply {
                        setHasSignature(1)
                        setPublicKeyAlgorithmName(createAsciiString(sigAlgorithmName))
                        setPublicKeyBlob(createByteString(publicKeyBlob))
                        setServerHostKey(createByteString(hostBoundKeyBlob))
                        setSignature(createByteString(signature))
                        _check()
                    }
                    setMethodSpecificFields(pubkeyAuth)
                } else {
                    setMethodName(createAsciiString("publickey"))
                    val pubkeyAuth = UserauthRequestPublickey().apply {
                        setHasSignature(1)
                        setPublicKeyAlgorithmName(createAsciiString(sigAlgorithmName))
                        setPublicKeyBlob(createByteString(publicKeyBlob))
                        setSignature(createByteString(signature))
                        _check()
                    }
                    setMethodSpecificFields(pubkeyAuth)
                }
                _check()
            }

            val deferred = CompletableDeferred<Boolean>()
            dispatchCommand("BeginPublicKeyAuthentication") { beginAuthentication() }
            pendingAuth.set(deferred)

            writePacket(
                SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
                req.toByteArray(),
            )

            try {
                val success = deferred.await()
                return if (success) {
                    PublicAuthResult.Success
                } else {
                    PublicAuthResult.Failure(allowedAuthentications ?: emptySet())
                }
            } finally {
                pendingAuth.clearIfSame(deferred)
            }
        } catch (e: Exception) {
            logger.error("Public key authentication error", e)
            return PublicAuthResult.Error(e.message ?: "Public key authentication error", e)
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

    private fun buildHostBoundSignatureData(
        sessionId: ByteArray,
        username: String,
        serviceName: String,
        algorithmName: String,
        publicKeyBlob: ByteArray,
        serverHostKeyBlob: ByteArray,
    ): ByteArray {
        val data = UserauthPublickeyHostboundSignatureData().apply {
            setSessionIdentifier(createByteString(sessionId))
            setMessageType(byteArrayOf(50))
            setUserName(createByteString(username.toByteArray(Charsets.UTF_8)))
            setServiceName(createByteString(serviceName.toByteArray(Charsets.US_ASCII)))
            setMethodName(createByteString(METHOD_PUBLICKEY_HOSTBOUND.toByteArray(Charsets.US_ASCII)))
            setHasSignature(byteArrayOf(1))
            setPublicKeyAlgorithmName(createByteString(algorithmName.toByteArray(Charsets.US_ASCII)))
            setPublicKeyBlob(createByteString(publicKeyBlob))
            setServerHostKey(createByteString(serverHostKeyBlob))
            _check()
        }
        return data.toByteArray()
    }

    private fun negotiateRsaAlgorithm(): String? = SignatureEntry.negotiateRsaAlgorithm(
        serverSigAlgs,
        hostKeyAlgorithms.split(',').filter { it.isNotEmpty() }.toSet(),
    )

    /**
     * Authenticate using the strategy-based [AuthHandler] flow.
     *
     * Drives the authentication per RFC 4252: none → publickey probe → sign →
     * keyboard-interactive → password.
     */
    internal suspend fun authenticate(username: String, handler: AuthHandler): PublicAuthResult {
        val channel = Channel<InternalAuthResult>(Channel.UNLIMITED)
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
        channel: Channel<InternalAuthResult>,
    ): PublicAuthResult {
        if (allowedAuthentications == null) {
            // Step 1: Send "none" auth to discover allowed methods
            sendAuthRequest(username, "none") {
                val noneAuth = UserauthRequestNone().apply { _check() }
                setMethodSpecificFields(noneAuth)
            }

            val noneResult = receiveAuthResult(channel, handler)
            if (noneResult is InternalAuthResult.Success) return PublicAuthResult.Success
            if (noneResult !is InternalAuthResult.Failure) return PublicAuthResult.Error("Unexpected response to 'none' auth: $noneResult")

            allowedAuthentications = noneResult.allowedMethods
        }

        val allowedMethods = allowedAuthentications!!
        handler.onAuthMethodsAvailable(allowedMethods)

        // Step 2: Public key phase
        if ("publickey" in allowedMethods) {
            val keys = handler.onPublicKeysNeeded()
            for (key in keys) {
                if (key in triedPublicKeys) continue
                val probeResult = probePublicKey(username, key, handler, channel)
                if (probeResult is InternalAuthResult.Success) return PublicAuthResult.Success
                if (probeResult is InternalAuthResult.PkOk) {
                    triedPublicKeys.add(key)
                    val signResult = signPublicKey(username, key, handler, channel)
                    if (signResult) return PublicAuthResult.Success
                } else {
                    triedPublicKeys.add(key)
                }
                if (probeResult is InternalAuthResult.Failure) {
                    allowedAuthentications = probeResult.allowedMethods
                }
                // InternalAuthResult.Failure → try next key
            }
        }

        for (method in selectPasswordMethods(allowedMethods, preferPasswordAuth)) {
            when (method) {
                is AuthMethod.KeyboardInteractive -> {
                    val kbdResult = doKeyboardInteractive(username, handler, channel)
                    if (kbdResult) return PublicAuthResult.Success
                }

                is AuthMethod.Password -> {
                    val password = handler.onPasswordNeeded() ?: return PublicAuthResult.Failure(allowedAuthentications ?: emptySet())
                    val passResult = doPasswordAuth(username, password, handler, channel)
                    if (passResult) return PublicAuthResult.Success
                }

                is AuthMethod.PublicKey,
                is AuthMethod.Unknown,
                -> {
                    logger.warn("Skipping unexpected auth method: ${AuthMethod.toSshName(method)}")
                }
            }
        }

        return PublicAuthResult.Failure(allowedAuthentications ?: emptySet())
    }

    private suspend fun probePublicKey(
        username: String,
        key: AuthPublicKey,
        handler: AuthHandler,
        channel: Channel<InternalAuthResult>,
    ): InternalAuthResult {
        val effectiveAlgorithmName = if (keyBlobAlgorithmName(key.publicKeyBlob) == KEY_TYPE_SSH_RSA) {
            negotiateRsaAlgorithm()
                ?: return InternalAuthResult.Failure(allowedAuthentications ?: setOf("publickey"), partialSuccess = false)
        } else {
            key.algorithmName
        }
        sendAuthRequest(username, "publickey") {
            val pubkeyAuth = UserauthRequestPublickey().apply {
                setHasSignature(0)
                setPublicKeyAlgorithmName(createAsciiString(effectiveAlgorithmName))
                setPublicKeyBlob(createByteString(key.publicKeyBlob))
                _check()
            }
            setMethodSpecificFields(pubkeyAuth)
        }
        return receiveAuthResult(channel, handler)
    }

    private suspend fun signPublicKey(
        username: String,
        key: AuthPublicKey,
        handler: AuthHandler,
        channel: Channel<InternalAuthResult>,
    ): Boolean {
        val sid = sessionId ?: throw SshException(ERROR_SESSION_ID_NOT_ESTABLISHED)
        val hostBoundKeyBlob = serverHostKeyBlob.takeIf { serverAdvertisesHostBound }

        val effectiveAlgorithmName = if (keyBlobAlgorithmName(key.publicKeyBlob) == KEY_TYPE_SSH_RSA) {
            negotiateRsaAlgorithm() ?: return false
        } else {
            key.algorithmName
        }

        val signatureData = if (hostBoundKeyBlob != null) {
            buildHostBoundSignatureData(sid, username, SERVICE_SSH_CONNECTION, effectiveAlgorithmName, key.publicKeyBlob, hostBoundKeyBlob)
        } else {
            buildSignatureData(sid, username, SERVICE_SSH_CONNECTION, effectiveAlgorithmName, key.publicKeyBlob)
        }

        val signingKey = if (effectiveAlgorithmName != key.algorithmName) key.copy(algorithmName = effectiveAlgorithmName) else key
        val signature = handler.onSignatureRequest(signingKey, signatureData) ?: return false

        if (hostBoundKeyBlob != null) {
            sendAuthRequest(username, METHOD_PUBLICKEY_HOSTBOUND) {
                val pubkeyAuth = UserauthRequestPublickeyHostbound().apply {
                    setHasSignature(1)
                    setPublicKeyAlgorithmName(createAsciiString(effectiveAlgorithmName))
                    setPublicKeyBlob(createByteString(key.publicKeyBlob))
                    setServerHostKey(createByteString(hostBoundKeyBlob))
                    setSignature(createByteString(signature))
                    _check()
                }
                setMethodSpecificFields(pubkeyAuth)
            }
        } else {
            sendAuthRequest(username, "publickey") {
                val pubkeyAuth = UserauthRequestPublickey().apply {
                    setHasSignature(1)
                    setPublicKeyAlgorithmName(createAsciiString(effectiveAlgorithmName))
                    setPublicKeyBlob(createByteString(key.publicKeyBlob))
                    setSignature(createByteString(signature))
                    _check()
                }
                setMethodSpecificFields(pubkeyAuth)
            }
        }

        val response = receiveAuthResult(channel, handler)
        return when (response) {
            is InternalAuthResult.Success -> true
            else -> false
        }
    }

    private suspend fun doKeyboardInteractive(
        username: String,
        handler: AuthHandler,
        channel: Channel<InternalAuthResult>,
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
                is InternalAuthResult.Banner -> {
                    handler.onBanner(result.message)
                }

                is InternalAuthResult.Success -> return true

                is InternalAuthResult.Failure -> {
                    allowedAuthentications = result.allowedMethods
                    return false
                }

                is InternalAuthResult.InfoRequest -> {
                    val responses = handler.onKeyboardInteractivePrompt(
                        result.name,
                        result.instruction,
                        result.prompts,
                    ) ?: return false

                    val responseMsg = SshMsgUserauthInfoResponse().apply {
                        setNumResponses(responses.size.toLong())
                        setResponses(
                            responses.map { response ->
                                createByteString(response.toByteArray(Charsets.UTF_8))
                            },
                        )
                        _check()
                    }

                    writePacket(
                        SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_61.id().toInt(),
                        responseMsg.toByteArray(),
                    )
                }

                is InternalAuthResult.PkOk -> {
                    // Unexpected during keyboard-interactive
                    return false
                }
            }
        }
    }

    private suspend fun doPasswordAuth(
        username: String,
        password: String,
        handler: AuthHandler,
        channel: Channel<InternalAuthResult>,
    ): Boolean {
        sendAuthRequest(username, "password") {
            val passAuth = UserauthRequestPassword().apply {
                setChangePassword(0)
                setPlaintextPassword(createUtf8String(password))
                _check()
            }
            setMethodSpecificFields(passAuth)
        }

        val response = receiveAuthResult(channel, handler)
        return when (val result = response) {
            is InternalAuthResult.Success -> true

            is InternalAuthResult.Failure -> {
                allowedAuthentications = result.allowedMethods
                false
            }

            else -> false
        }
    }

    private suspend fun receiveAuthResult(
        channel: Channel<InternalAuthResult>,
        handler: AuthHandler,
    ): InternalAuthResult {
        var result = channel.receive()
        while (result is InternalAuthResult.Banner) {
            handler.onBanner(result.message)
            result = channel.receive()
        }
        return result
    }

    private suspend fun sendAuthRequest(
        username: String,
        method: String,
        configure: SshMsgUserauthRequest.() -> Unit,
    ) {
        dispatchCommand("BeginAuthenticationRequest") { beginAuthentication() }
        val req = SshMsgUserauthRequest().apply {
            setUserName(createAsciiString(username))
            setServiceName(createAsciiString(SERVICE_SSH_CONNECTION))
            setMethodName(createAsciiString(method))
            configure()
            _check()
        }
        outboundPacketController.writePacket(
            SshEnums.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(),
            req.toByteArray(),
            beforeWrite = { currentAuthMethod = AuthMethod.fromString(method) },
        )
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
        outboundPacketController.beginKex()
        logger.debug("Sending KEX_INIT")
        val localKexAlgorithms = if (isRekeying) kexAlgorithms else initialKexAlgorithms

        val kexInit = SshMsgKexinit().apply {
            // Cookie (16 random bytes)
            val cookie = ByteArray(16).apply {
                SecureRandom().nextBytes(this)
            }
            setCookie(cookie)

            setKexAlgorithms(createNameList(localKexAlgorithms))
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

    private fun receiveKexInit(msg: SshMsgKexinit, initialExchange: Boolean): Boolean {
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

        val localKexAlgorithms = if (initialExchange) initialKexAlgorithms else kexAlgorithms
        val clientKexList = parseNameList(localKexAlgorithms)
        val serverKexList = serverKexAlgs.filter { it.isNotEmpty() }
        val clientKexStrict = "kex-strict-c-v00@openssh.com" in clientKexList
        val serverKexStrict = "kex-strict-s-v00@openssh.com" in serverKexList
        val strictKexNegotiated = clientKexStrict && serverKexStrict
        if (strictKexNegotiated) {
            logger.info("  Strict KEX enabled")
        }

        if (initialExchange) {
            serverAdvertisesExtInfo = "ext-info-s" in serverKexList
            if (serverAdvertisesExtInfo) {
                logger.info("  Server advertises EXT_INFO support")
            }
        }

        negotiatedKex = clientKexList.firstOrNull { it in serverKexList }
            ?: throw SshException("No matching KEX algorithm. Client: $localKexAlgorithms, Server: $serverKexAlgs")
        logger.info("  Negotiated KEX: $negotiatedKex")

        val clientHostKeyList = hostKeyAlgorithms.split(",")
        val matchingHostKey = clientHostKeyList.firstOrNull { it in serverHostKeyAlgs }
            ?: throw SshException("No matching host key algorithm. Client: $hostKeyAlgorithms, Server: $serverHostKeyAlgs")
        logger.info("  Negotiated host key: $matchingHostKey")
        negotiatedHostKeyAlgorithm = matchingHostKey

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

        return strictKexNegotiated
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
            ?: throw SshException(ERROR_CLIENT_PUBLIC_KEY_NOT_GENERATED)

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
            ?: throw SshException(ERROR_CLIENT_PUBLIC_KEY_NOT_GENERATED)

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

    private fun rekeyStarted() {
        logger.info("Re-key started")
        isRekeying = true
        rekeyTimerJob?.cancel()
    }

    private fun rekeyComplete() {
        logger.info("Re-key complete")
        packetIO.resetByteCounters()
        connectionScope.launch {
            withContext(stateMachineDispatcher) {
                while (pendingPingQueue.isNotEmpty()) {
                    val action = pendingPingQueue.removeFirst()
                    action()
                }
                isRekeying = false
                startRekeyTimer()
            }
        }
    }

    private fun startRekeyTimer() {
        rekeyTimerJob?.cancel()
        rekeyTimerJob = connectionScope.launch {
            delay(rekeyIntervalMs)
            if (!isRekeying && stateMachine.isPostAuthenticated()) {
                connectionScope.launch {
                    dispatchCommand("TimerRekey") { requestRekey() }
                }
            }
        }
    }

    private suspend fun sendKexDhGexInit() {
        val group = dhGexGroup ?: throw SshException("DH-GEX group not received")
        val dhGex = kex as? DiffieHellmanGroupExchange
            ?: throw SshException("KEX algorithm is not DH-GEX")
        dhGex.setGroup(
            BigInteger(1, group.p().body()),
            BigInteger(1, group.g().body()),
        )
        clientPublicKey = dhGex.generateClientKeys()

        val initMsg = SshMsgKexDhGexInit().apply {
            setE(createMpint(clientPublicKey!!))
            _check()
        }
        writePacket(
            SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_INIT.id().toInt(),
            initMsg.toByteArray(),
        )
    }

    private suspend fun receiveKexDhReply(msg: SshMsgKexdhReply) {
        logger.info("Received DH_REPLY from server")
        completeKex(
            serverHostKey = msg.serverKey().data(),
            serverPublicKey = msg.f().body(),
            signature = msg.signatureH().data(),
        )
    }

    private suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) {
        logger.info("Received ECDH_REPLY from server")
        completeKex(
            serverHostKey = msg.kS().data(),
            serverPublicKey = msg.qS().data(),
            signature = msg.signatureH().data(),
        )
    }

    private suspend fun completeKex(serverHostKey: ByteArray, serverPublicKey: ByteArray, signature: ByteArray) {
        val kexAlg = kex ?: throw SshException(ERROR_NO_KEX_ALGORITHM_INITIALIZED)
        val sv = serverVersion ?: throw SshException("Server version not received")
        val cki = clientKexInit ?: throw SshException("Client KEX_INIT not sent")
        val ski = serverKexInit ?: throw SshException("Server KEX_INIT not received")
        val cpk = clientPublicKey ?: throw SshException(ERROR_CLIENT_PUBLIC_KEY_NOT_GENERATED)

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
            secret,
        )

        val hash = exchangeHash
            ?: throw SshException("Exchange hash computation failed")

        val existingKey = serverHostKeyBlob
        if (existingKey != null && !serverHostKey.contentEquals(existingKey)) {
            logger.error("Host key changed during re-key — possible MITM attack")
            throw SshException("Host key changed during re-key")
        }

        val negotiatedAlg = negotiatedHostKeyAlgorithm
            ?: throw SshException("No host key algorithm negotiated")
        if (!SignatureVerifier.verify(serverHostKey, signature, hash, negotiatedAlg)) {
            logger.error("Server signature verification failed")
            throw SshException("Server signature verification failed")
        }
        logger.info("Server signature verified")

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

        val trusted = hostKeyVerifier.verify(publicKey)

        if (!trusted) {
            logger.error("Host key verification failed")
            throw HostKeyRejectedException(publicKey)
        }
        logger.info("Host key verified")

        serverHostKeyBlob = serverHostKey
        if (sessionId == null) {
            sessionId = hash.copyOf()
        }

        clientKexInit?.fill(0)
        clientKexInit = null
        serverKexInit?.fill(0)
        serverKexInit = null
        clientPublicKey?.fill(0)
        clientPublicKey = null
    }

    private suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) {
        logger.info("Received DH_GEX_REPLY from server")
        completeKex(
            serverHostKey = msg.serverPublicHostKey().data(),
            serverPublicKey = msg.f().body(),
            signature = msg.signatureH().data(),
        )
    }

    private suspend fun sendNewKeys(resetSequenceNumber: Boolean) {
        logger.info("Sending NEW_KEYS")
        prepareEncryption()
        try {
            outboundPacketController.writePacket(
                SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt(),
                afterWrite = {
                    val protection = pendingProtection
                        ?: throw SshException("No staged packet protection")
                    protection.installOutbound(packetIO)
                    packetIO.enableSendCompression(pendingSendCompressor, pendingCompressionImmediate)
                    pendingSendCompressor = null
                    if (resetSequenceNumber) {
                        packetIO.resetSendSequenceNumber()
                    }
                    outboundPacketController.completeKex()
                },
            )
        } catch (e: Exception) {
            discardPendingEncryption()
            throw e
        }
    }

    private suspend fun sendClientExtInfo() {
        if (clientExtInfoSent) {
            logger.info("Skipping client SSH_MSG_EXT_INFO; already sent during initial key exchange")
            return
        }
        if (isRekeying) {
            logger.info("Skipping client SSH_MSG_EXT_INFO during re-key")
            return
        }
        if (!serverAdvertisesExtInfo) {
            logger.info("Skipping client SSH_MSG_EXT_INFO; server did not advertise ext-info-s")
            return
        }
        logger.info("Sending client SSH_MSG_EXT_INFO")
        val msg = SshMsgExtInfo()
        val extensions = listOf(
            "ext-info-in-auth@openssh.com",
        )
        msg.setNumExtensions(extensions.size.toLong())
        msg.setExtensions(
            extensions.mapTo(ArrayList()) { name ->
                SshMsgExtInfo.Extension().apply {
                    set_root(msg)
                    set_parent(msg)
                    setExtensionName(createAsciiString(name))
                    setExtensionValue(createByteString("0".toByteArray(Charsets.US_ASCII)))
                    _check()
                }
            },
        )
        msg._check()
        writePacket(SshEnums.MessageType.SSH_MSG_EXT_INFO.id().toInt(), msg.toByteArray())
        clientExtInfoSent = true
    }

    private fun processServerExtInfo(extInfo: SshMsgExtInfo) {
        if (!serverAdvertisesExtInfo) {
            logger.warn("Ignoring SSH_MSG_EXT_INFO because server did not advertise ext-info-s")
            return
        }
        if (serverExtInfoReceivedCount >= 2) {
            logger.warn("Ignoring unexpected extra SSH_MSG_EXT_INFO from server")
            return
        }
        val initialExtInfo = serverExtInfoReceivedCount == 0
        serverExtInfoReceivedCount++

        if (initialExtInfo) {
            serverAdvertisesHostBound = false
            serverSigAlgs = null
            serverSupportsPing = false
        }

        for (ext in extInfo.extensions()) {
            when (ext.extensionName().value()) {
                "publickey-hostbound@openssh.com" -> {
                    if (initialExtInfo) {
                        serverAdvertisesHostBound = true
                        logger.info("Server advertises publickey-hostbound@openssh.com")
                    }
                }

                "server-sig-algs" -> {
                    val algs = String(ext.extensionValue().data(), Charsets.UTF_8)
                    serverSigAlgs = algs.split(",").filter { it.isNotEmpty() }.toSet()
                    logger.info("Server advertises server-sig-algs: $algs")
                }

                "ping@openssh.com" -> {
                    if (initialExtInfo) {
                        serverSupportsPing = true
                        logger.info("Server advertises ping@openssh.com")
                    }
                }
            }
        }
    }

    private fun receiveNewKeys(resetSequenceNumber: Boolean) {
        logger.info("Received NEW_KEYS from server")
        val protection = pendingProtection
            ?: throw SshException("No staged packet protection")
        protection.installInbound(packetIO)
        packetIO.enableReceiveCompression(pendingReceiveCompressor, pendingCompressionImmediate)
        pendingReceiveCompressor = null
        if (resetSequenceNumber) {
            packetIO.resetReceiveSequenceNumber()
        }
    }

    private fun activateEncryption() {
        logger.info("Encryption active")
        pendingProtection?.destroy()
        pendingProtection = null
        pendingSendCompressor = null
        pendingReceiveCompressor = null

        kex?.zeroize()
        kex = null
        sharedSecret?.fill(0)
        sharedSecret = null
        exchangeHash?.fill(0)
        exchangeHash = null
    }

    private fun prepareEncryption() {
        discardPendingEncryption()
        val encC2S = negotiatedEncryptionC2S
            ?: throw SshException("No encryption algorithm negotiated for client-to-server")
        val encS2C = negotiatedEncryptionS2C
            ?: throw SshException("No encryption algorithm negotiated for server-to-client")

        val cipherC2S = CipherEntry.fromSshName(encC2S)
            ?: throw SshException("Unknown cipher: $encC2S")

        if (cipherC2S.isAead) {
            pendingProtection = prepareAeadEncryption(encC2S, encS2C)
        } else {
            pendingProtection = prepareNonAeadEncryption(encC2S, encS2C)
        }

        val compC2SName = negotiatedCompressionC2S
        val compS2CName = negotiatedCompressionS2C
        if (compC2SName != null && compS2CName != null) {
            val compC2S = CompressionEntry.fromSshName(compC2SName)
            val compS2C = CompressionEntry.fromSshName(compS2CName)
            if (compC2S != null && compS2C != null) {
                pendingCompressionImmediate = isRekeying || (!compC2S.delayedActivation && !compS2C.delayedActivation)
                pendingSendCompressor = compC2S.create()
                pendingReceiveCompressor = compS2C.create()
                logger.info("Compression staged: c2s=$compC2SName, s2c=$compS2CName, immediate=$pendingCompressionImmediate")
            }
        }
    }

    private fun prepareAeadEncryption(encC2S: String, encS2C: String): PendingProtection {
        val entryC2S = CipherEntry.fromSshName(encC2S)
            ?: throw SshException("Unknown AEAD cipher: $encC2S")
        val entryS2C = CipherEntry.fromSshName(encS2C)
            ?: throw SshException("Unknown AEAD cipher: $encS2C")

        val keyLength = maxOf(entryC2S.keyLength, entryS2C.keyLength)
        val ivLength = maxOf(entryC2S.ivLength, entryS2C.ivLength)

        val secret = sharedSecret ?: throw SshException("Shared secret not computed")
        val hash = exchangeHash ?: throw SshException("Exchange hash not computed")
        val sid = sessionId ?: throw SshException(ERROR_SESSION_ID_NOT_ESTABLISHED)
        val kexAlg = kex ?: throw SshException(ERROR_NO_KEX_ALGORITHM_INITIALIZED)

        val keyDerivation = KeyDerivation(
            secret,
            hash,
            sid,
            kexAlg.hashAlgorithm,
        )

        val keys = keyDerivation.deriveKeys(
            ivLength = ivLength,
            keyLength = keyLength,
            macKeyLength = 0,
        )

        val c2sKey = keys.encryptionKeyClientToServer.copyOf(entryC2S.keyLength)
        val s2cKey = keys.encryptionKeyServerToClient.copyOf(entryS2C.keyLength)
        val c2sIv = if (entryC2S.ivLength > 0) keys.initialIvClientToServer.copyOf(entryC2S.ivLength) else ByteArray(0)
        val s2cIv = if (entryS2C.ivLength > 0) keys.initialIvServerToClient.copyOf(entryS2C.ivLength) else ByteArray(0)

        try {
            val c2sAead = (entryC2S.create(c2sKey, c2sIv, true) as EncryptionInstance.Aead).aead
            val s2cAead = try {
                (entryS2C.create(s2cKey, s2cIv, false) as EncryptionInstance.Aead).aead
            } catch (e: Exception) {
                c2sAead.destroy()
                throw e
            }
            return PendingAeadProtection(c2sAead, s2cAead)
        } finally {
            keys.zeroize()
            c2sKey.fill(0)
            s2cKey.fill(0)
            c2sIv.fill(0)
            s2cIv.fill(0)
        }
    }

    private fun prepareNonAeadEncryption(encC2S: String, encS2C: String): PendingProtection {
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
        val sid = sessionId ?: throw SshException(ERROR_SESSION_ID_NOT_ESTABLISHED)
        val kexAlg = kex ?: throw SshException(ERROR_NO_KEX_ALGORITHM_INITIALIZED)

        val keyDerivation = KeyDerivation(
            secret,
            hash,
            sid,
            kexAlg.hashAlgorithm,
        )

        val keys = keyDerivation.deriveKeys(
            ivLength = ivLength,
            keyLength = keyLength,
            macKeyLength = macKeyLength,
        )

        val c2sCipherKey = keys.encryptionKeyClientToServer.copyOf(cipherEntryC2S.keyLength)
        val s2cCipherKey = keys.encryptionKeyServerToClient.copyOf(cipherEntryS2C.keyLength)
        val c2sIv = keys.initialIvClientToServer.copyOf(cipherEntryC2S.ivLength)
        val s2cIv = keys.initialIvServerToClient.copyOf(cipherEntryS2C.ivLength)

        try {
            val clientToServerCipher = (cipherEntryC2S.create(c2sCipherKey, c2sIv, true) as EncryptionInstance.Cipher).cipher
            var serverToClientCipher: PacketCipher? = null
            var clientToServerMac: PacketMac? = null
            try {
                serverToClientCipher = (cipherEntryS2C.create(s2cCipherKey, s2cIv, false) as EncryptionInstance.Cipher).cipher
                clientToServerMac = macEntryC2S.create(keys.integrityKeyClientToServer)
                val serverToClientMac = macEntryS2C.create(keys.integrityKeyServerToClient)
                return PendingCipherProtection(
                    clientToServerCipher,
                    clientToServerMac,
                    macEntryC2S.isEtm,
                    serverToClientCipher,
                    serverToClientMac,
                    macEntryS2C.isEtm,
                )
            } catch (e: Exception) {
                clientToServerCipher.destroy()
                serverToClientCipher?.destroy()
                clientToServerMac?.destroy()
                throw e
            }
        } finally {
            keys.zeroize()
            c2sCipherKey.fill(0)
            s2cCipherKey.fill(0)
            c2sIv.fill(0)
            s2cIv.fill(0)
        }
    }

    private fun discardPendingEncryption() {
        pendingProtection?.destroy()
        pendingProtection = null
        pendingSendCompressor = null
        pendingReceiveCompressor = null
        pendingCompressionImmediate = false
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
        startRekeyTimer()
        pendingConnect?.complete(ConnectResult.Success)
        pendingConnect = null
    }

    private fun startAuthentication() {
        logger.info("Starting authentication")
    }

    private fun authenticationSuccess() {
        logger.info("Authentication successful")
        authRequestPending = false
        packetIO.activateCompression()
        pendingAuth.complete(true)
    }

    private fun authenticationFailure() {
        logger.warn("Authentication failed")
        authRequestPending = false
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
        val ch = authResultChannel
        if (ch != null) {
            val message = msg.message().value()
            if (ch.trySend(InternalAuthResult.Banner(message)).isFailure) {
                logger.warn("Failed to deliver banner to auth channel")
            }
        } else {
            logger.info("SSH banner: ${msg.message().value()}")
        }
    }

    private fun debug(msg: SshMsgDebug) {
        logger.debug("SSH debug: ${msg.message()}")
    }

    private fun ignore() {
        logger.trace("Received IGNORE message")
    }

    private suspend fun disconnect() {
        logger.info("Disconnecting (received SSH_MSG_DISCONNECT from server)")
        isRekeying = false
        authRequestPending = false
        _disconnectedFlow.tryEmit(null)
        closeTransport()
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
            val maxPacketSize = boundRemotePacketSize(msg.maximumPacketSize())
            if (maxPacketSize == null) {
                logger.warn("Rejecting channel with invalid maximum packet size: ${msg.maximumPacketSize()}")
                rejectChannelOpen(senderChannel, channelType)
                return
            }

            logger.info("Received CHANNEL_OPEN: type=$channelType, sender=$senderChannel")

            when (channelType) {
                "auth-agent@openssh.com" -> {
                    if (agentProvider == null) {
                        rejectChannelOpen(senderChannel, channelType)
                        return
                    }
                    val verifiedSessionId = sessionId
                    val verifiedServerHostKey = serverHostKeyBlob
                    if (verifiedSessionId == null || verifiedSessionId.isEmpty() ||
                        verifiedSessionId.size > AGENT_MAX_SESSION_ID_LENGTH ||
                        verifiedServerHostKey == null || verifiedServerHostKey.isEmpty()
                    ) {
                        logger.error("Rejecting agent channel without a verified SSH session binding")
                        rejectChannelOpen(senderChannel, channelType)
                        return
                    }
                    val localChannelNumber = allocateChannelNumber()

                    val sessionInfo = AgentSessionInfo(
                        sessionId = verifiedSessionId.copyOf(),
                        serverHostKey = verifiedServerHostKey.copyOf(),
                    )
                    val handler = AgentProtocolHandler(agentProvider!!, sessionInfo)
                    val agentChannel = AgentChannel(
                        handler,
                        this,
                        connectionScope,
                        localChannelNumber,
                        senderChannel,
                        maxPacketSize,
                        initialWindow,
                    )

                    channelRegistry.register(agentChannel)
                    try {
                        sendChannelOpenConfirmation(
                            recipientChannel = senderChannel,
                            senderChannel = localChannelNumber,
                            initialWindowSize = 64 * 1024,
                            maximumPacketSize = 32 * 1024,
                        )
                    } catch (failure: Throwable) {
                        channelRegistry.unregister(localChannelNumber)
                        agentChannel.onDisconnected()
                        throw failure
                    }
                    logger.info("Accepted agent channel: local=$localChannelNumber, remote=$senderChannel")
                }

                CHANNEL_FORWARDED_TCPIP -> {
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
                logger.warn("Failed to parse $CHANNEL_FORWARDED_TCPIP channel data")
                rejectChannelOpen(senderChannel, CHANNEL_FORWARDED_TCPIP)
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
                rejectChannelOpen(senderChannel, CHANNEL_FORWARDED_TCPIP)
                return
            }

            handler(connectedAddr, connectedPort, originAddr, originPort, senderChannel, initialWindow, maxPacketSize)
        } catch (e: Exception) {
            logger.error("Failed to handle $CHANNEL_FORWARDED_TCPIP", e)
            rejectChannelOpen(senderChannel, CHANNEL_FORWARDED_TCPIP)
        }
    }

    private suspend fun rejectChannelOpen(senderChannel: Int, channelType: String) {
        logger.warn("Rejecting channel open: type=$channelType")
        sendChannelOpenFailure(
            recipientChannel = senderChannel,
            reasonCode = 3,
            description = "Channel type not supported",
            languageTag = "",
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
            msg.toByteArray(),
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
            msg.toByteArray(),
        )
    }

    suspend fun close() {
        connectionScope.cancel()
        closeTransport()
        packetLoopJob?.join()
        packetLoopJob = null

        withContext(stateMachineDispatcher) {
            val error = Exception("Connection closed")
            for ((_, pending) in pendingPings) {
                pending.deferred.complete(PingResult.Failure(error))
            }
            pendingPings.clear()
            pendingPingQueue.clear()
        }

        sessionId?.fill(0)
        sessionId = null
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
            msg.toByteArray(),
        )
    }

    private suspend fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) {
        logger.info("Channel open confirmed")
        val recipientChannel = msg.recipientChannel().toInt()
        val pending = channelRegistry.findPendingSession(recipientChannel)
            ?: throw ProtocolViolationException("Channel confirmation with no pending open for channel $recipientChannel")
        if (!pending.lifecycle.openConfirmed {
                channelRegistry.bindRemoteRecipient(pending, msg.senderChannel().toInt())
                pending.deferred.complete(msg)
            }
        ) {
            throw ProtocolViolationException("Channel confirmation in ${pending.lifecycle.state} state for channel $recipientChannel")
        }
    }

    private suspend fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) {
        logger.error("Channel open failed: ${msg.reasonCode()}")
        val recipientChannel = msg.recipientChannel().toInt()
        val pending = channelRegistry.findPendingSession(recipientChannel)
            ?: throw ProtocolViolationException("Channel failure with no pending open for channel $recipientChannel")
        if (!pending.lifecycle.openFailed {
                channelRegistry.removePendingSessionIf(recipientChannel, pending.deferred)
                pending.deferred.complete(null)
            }
        ) {
            throw ProtocolViolationException("Channel failure in ${pending.lifecycle.state} state for channel $recipientChannel")
        }
    }

    private suspend fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest) {
        logger.debug("Sending CHANNEL_REQUEST: $requestType (channel=$recipientChannel, wantReply=$wantReply)")
        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST.id().toInt(),
            message.toByteArray(),
        )
    }

    private fun receiveChannelSuccess(recipientChannel: Int) {
        logger.debug("Channel request succeeded")
        val pending = pendingChannelRequests.remove(recipientChannel)
            ?: throw ProtocolViolationException("Channel success with no pending request for channel $recipientChannel")
        pending.complete(true)
    }

    private fun receiveChannelFailure(recipientChannel: Int) {
        logger.warn("Channel request failed")
        val pending = pendingChannelRequests.remove(recipientChannel)
            ?: throw ProtocolViolationException("Channel failure with no pending request for channel $recipientChannel")
        pending.complete(false)
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
        val lifecycle = SshChannelStateMachine(SshChannelState.OPENING)
        channelRegistry.registerPendingForwarding(
            localChannelNumber,
            deferred,
            maxPacketSize,
            initialWindowSize,
            lifecycle,
        )

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

        return try {
            writePacket(
                SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN.id().toInt(),
                msg.toByteArray(),
            )
            deferred.await()
        } finally {
            channelRegistry.removePendingForwardingIf(localChannelNumber, deferred)?.lifecycle?.disconnect {}
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
        }
        writePacket(
            SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST.id().toInt(),
            msg.toByteArray(),
        )

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
            msg.toByteArray(),
        )
    }

    internal fun registerRemoteForwarder(key: String, handler: suspend (String, Int, String, Int, Int, Long, Int) -> Unit) {
        remoteForwarders[key] = handler
    }

    internal fun unregisterRemoteForwarder(key: String) {
        remoteForwarders.remove(key)
    }

    internal fun registerForwardingChannel(channel: ForwardingChannel) {
        channelRegistry.register(channel)
    }

    internal fun unregisterForwardingChannel(channel: ForwardingChannel) {
        channelRegistry.unregister(channel.localChannelNumber)
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
    private inner class InboundPacketController {
        private val packetsReceivedDuringRekey = ArrayDeque<PacketIO.ReceivedPacket>()

        private fun requireAccepted(accepted: Boolean, messageType: Any) {
            if (!accepted) {
                throw ProtocolViolationException("Unexpected SSH packet $messageType in the current protocol state")
            }
        }

        suspend fun processNextPacket() {
            val queuedPacket = withContext(stateMachineDispatcher) {
                if (stateMachine.isKexInProgress()) null else packetsReceivedDuringRekey.removeFirstOrNull()
            }
            val receivedPacket = queuedPacket ?: packetIO.readPacketWithSequence()
            val packet = receivedPacket.payload
            val packetSequenceNumber = receivedPacket.sequenceNumber
            val messageNumber = receivedPacket.messageNumber
            val msgType = packet.messageType()
            logger.debug("Received packet: $msgType")

            withContext(stateMachineDispatcher) {
                if (!isKeyExchangeMessage(messageNumber)) {
                    val description = "Non-KEX packet $msgType is forbidden during strict initial key exchange"
                    if (!stateMachine.authorizeNonKexPacket(description)) {
                        throw ProtocolViolationException(description, responseSent = true)
                    }
                }

                if (isRekeying && stateMachine.isKexInProgress() && messageNumber >= SSH_MSG_USERAUTH_REQUEST_ID) {
                    if (packetsReceivedDuringRekey.size >= MAX_REKEY_IN_FLIGHT_PACKETS) {
                        throw ProtocolViolationException("Too many higher-layer packets received during key exchange")
                    }
                    packetsReceivedDuringRekey.addLast(receivedPacket)
                    return@withContext
                }

                when (msgType) {
                    SshEnums.MessageType.SSH_MSG_KEXINIT -> {
                        if (stateMachine.isKexInProgress() && !stateMachine.isWaitingForKexInit()) {
                            val description = "Unexpected SSH_MSG_KEXINIT while key exchange is already in progress"
                            requireAccepted(stateMachine.unexpectedKexInit(description), msgType)
                            throw ProtocolViolationException(description, responseSent = true)
                        }
                        val kexInitMsgType = msgType.id().toByte()
                        serverKexInit = byteArrayOf(kexInitMsgType) + packet._raw_body()
                        val kexInit = packet.body() as SshMsgKexinit
                        if (stateMachine.isPostAuthenticated()) {
                            requireAccepted(stateMachine.requestRekey(), msgType)
                        }
                        requireAccepted(stateMachine.receiveKexInit(kexInit), msgType)
                        if (stateMachine.isDisconnected()) {
                            val description = "SSH_MSG_KEXINIT was not the first packet during strict initial key exchange"
                            throw ProtocolViolationException(description, responseSent = true)
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_NEWKEYS -> {
                        requireAccepted(stateMachine.receiveNewKeys(), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_SERVICE_ACCEPT -> {
                        val msg = parseBody<SshMsgServiceAccept>(packet)
                        requireAccepted(stateMachine.receiveServiceAccept(msg.serviceName().value()), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_IGNORE -> {
                        requireAccepted(stateMachine.receiveIgnore(), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_DEBUG -> {
                        requireAccepted(stateMachine.receiveDebug(packet.body() as SshMsgDebug), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_UNIMPLEMENTED -> {
                        logger.debug("Peer reported packet ${parseBody<SshMsgUnimplemented>(packet).packetSequence()} as unimplemented")
                    }

                    SshEnums.MessageType.SSH_MSG_GLOBAL_REQUEST -> {
                        try {
                            val rawBody = packet._raw_body()
                            val stream = ByteBufferKaitaiStream(rawBody)
                            val globalRequestMsg = SshMsgGlobalRequest(stream)
                            globalRequestMsg._read()
                            requireAccepted(stateMachine.receiveGlobalRequest(globalRequestMsg), msgType)
                        } catch (e: ProtocolViolationException) {
                            throw e
                        } catch (e: Exception) {
                            throw ProtocolViolationException("Malformed SSH_MSG_GLOBAL_REQUEST", e)
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        handleIncomingChannelOpen(packet)
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val confirmationMsg = parseBody<SshMsgChannelOpenConfirmation>(packet)
                        val recipientChannel = confirmationMsg.recipientChannel().toInt()
                        val pending = channelRegistry.findPendingForwarding(recipientChannel)
                        if (pending != null) {
                            val remoteChannelNumber = confirmationMsg.senderChannel().toInt()
                            val remoteWindow = confirmationMsg.initialWindowSize()
                            val remoteMaxPacketSize = boundRemotePacketSize(confirmationMsg.maximumPacketSize())
                            var invalidPacketSize = false
                            if (!pending.lifecycle.openConfirmed {
                                    channelRegistry.bindRemoteRecipient(pending, remoteChannelNumber)
                                    if (remoteMaxPacketSize == null) {
                                        invalidPacketSize = true
                                        channelRegistry.removePendingForwardingIf(recipientChannel, pending.deferred)
                                        pending.deferred.complete(null)
                                    } else {
                                        logger.info("Direct-tcpip channel opened: local=$recipientChannel, remote=$remoteChannelNumber")
                                        val channel = ForwardingChannel(
                                            this@SshConnection,
                                            connectionScope,
                                            recipientChannel,
                                            remoteChannelNumber,
                                            remoteMaxPacketSize,
                                            remoteWindowSizeInitial = remoteWindow,
                                            initialWindowSize = pending.initialWindowSize,
                                            lifecycle = pending.lifecycle,
                                        )
                                        channelRegistry.promote(pending, channel)
                                        pending.deferred.complete(channel)
                                    }
                                }
                            ) {
                                throw ProtocolViolationException("Channel confirmation in ${pending.lifecycle.state} state for channel $recipientChannel")
                            }
                            if (invalidPacketSize) {
                                logger.warn("Rejecting channel confirmation with invalid maximum packet size: ${confirmationMsg.maximumPacketSize()}")
                                pending.lifecycle.sendClose { sendChannelClose(remoteChannelNumber) }
                            }
                        } else {
                            requireAccepted(stateMachine.receiveChannelOpenConfirmation(confirmationMsg), msgType)
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val failureMsg = parseBody<SshMsgChannelOpenFailure>(packet)
                        val recipientChannel = failureMsg.recipientChannel().toInt()
                        val pending = channelRegistry.findPendingForwarding(recipientChannel)
                        if (pending != null) {
                            if (!pending.lifecycle.openFailed {
                                    channelRegistry.removePendingForwardingIf(recipientChannel, pending.deferred)
                                    pending.deferred.complete(null)
                                }
                            ) {
                                throw ProtocolViolationException("Channel failure in ${pending.lifecycle.state} state for channel $recipientChannel")
                            }
                        } else {
                            requireAccepted(stateMachine.receiveChannelOpenFailure(failureMsg), msgType)
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_DATA -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val msg = parseBody<SshMsgChannelData>(packet)
                        val recipientChannel = msg.recipientChannel().toInt()
                        when (val entry = channelRegistry.findByLocalRecipient(recipientChannel)) {
                            is SshChannelRegistry.Entry.Established.Session -> entry.channel.onData(msg.data().data())
                            is SshChannelRegistry.Entry.Established.Agent -> entry.channel.handleData(msg.data().data())
                            is SshChannelRegistry.Entry.Established.Forwarding -> entry.channel.onData(msg.data().data())
                            null -> throw ProtocolViolationException("Channel data for unknown channel $recipientChannel")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_EXTENDED_DATA -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val msg = parseBody<SshMsgChannelExtendedData>(packet)
                        val recipientChannel = msg.recipientChannel().toInt()
                        when (val entry = channelRegistry.findByLocalRecipient(recipientChannel)) {
                            is SshChannelRegistry.Entry.Established.Session ->
                                entry.channel.onExtendedData(msg.dataTypeCode().toInt(), msg.data().data())

                            is SshChannelRegistry.Entry.Established.Agent,
                            is SshChannelRegistry.Entry.Established.Forwarding,
                            -> throw ProtocolViolationException("Extended data is invalid for channel $recipientChannel")

                            null -> throw ProtocolViolationException("Extended data for unknown channel $recipientChannel")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val msg = parseBody<SshMsgChannelWindowAdjust>(packet)
                        val recipientChannel = msg.recipientChannel().toInt()
                        when (val entry = channelRegistry.findByLocalRecipient(recipientChannel)) {
                            is SshChannelRegistry.Entry.Established.Session -> entry.channel.onWindowAdjust(msg.bytesToAdd())
                            is SshChannelRegistry.Entry.Established.Agent -> entry.channel.onWindowAdjust(msg.bytesToAdd())
                            is SshChannelRegistry.Entry.Established.Forwarding -> entry.channel.onWindowAdjust(msg.bytesToAdd())
                            null -> throw ProtocolViolationException("Window adjust for unknown channel $recipientChannel")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_EOF -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val msg = parseBody<SshMsgChannelEof>(packet)
                        val recipientChannel = msg.recipientChannel().toInt()
                        when (val entry = channelRegistry.findByLocalRecipient(recipientChannel)) {
                            is SshChannelRegistry.Entry.Established.Session -> entry.channel.onEof()
                            is SshChannelRegistry.Entry.Established.Agent -> entry.channel.onEof()
                            is SshChannelRegistry.Entry.Established.Forwarding -> entry.channel.onEof()
                            null -> throw ProtocolViolationException("EOF for unknown channel $recipientChannel")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val msg = parseBody<SshMsgChannelClose>(packet)
                        val recipientChannel = msg.recipientChannel().toInt()
                        logger.debug("Received CHANNEL_CLOSE for local channel $recipientChannel")
                        when (val entry = channelRegistry.findByLocalRecipient(recipientChannel)) {
                            is SshChannelRegistry.Entry.Established.Session -> entry.channel.onClose()
                            is SshChannelRegistry.Entry.Established.Agent -> entry.channel.onClose()
                            is SshChannelRegistry.Entry.Established.Forwarding -> entry.channel.onClose()
                            null -> throw ProtocolViolationException("Close for unknown channel $recipientChannel")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_REQUEST -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val rawBody = packet._raw_body()
                        val stream = ByteBufferKaitaiStream(rawBody)
                        val msg = SshMsgChannelRequest(stream)
                        msg._read()
                        val recipientChannel = msg.recipientChannel().toInt()
                        val deliverRequest = suspend {
                            logger.debug("Received channel request: ${msg.requestType().value()} (want_reply=${msg.wantReply() != 0})")
                        }
                        val requestAccepted = when (val entry = channelRegistry.findByLocalRecipient(recipientChannel)) {
                            is SshChannelRegistry.Entry.Established.Session -> entry.channel.receiveRequest {
                                deliverRequest()
                                // RFC 4254 section 6.10: surface how the remote
                                // process terminated to exitInfo waiters.
                                when (val fields = msg.requestSpecificFields()) {
                                    is ChannelRequestExitStatus -> entry.channel.receiveExitInfo(
                                        SessionExit.Status(fields.exitStatus()),
                                    )

                                    is ChannelRequestExitSignal -> entry.channel.receiveExitInfo(
                                        SessionExit.Signal(
                                            signalName = fields.signalName().data().decodeToString(),
                                            coreDumped = fields.coreDumped() != 0,
                                            errorMessage = fields.errorMessage().value(),
                                        ),
                                    )

                                    else -> Unit
                                }
                            }

                            is SshChannelRegistry.Entry.Established.Agent -> entry.channel.receiveRequest(deliverRequest)

                            is SshChannelRegistry.Entry.Established.Forwarding -> entry.channel.receiveRequest(deliverRequest)

                            null -> throw ProtocolViolationException("Channel request for unknown channel $recipientChannel")
                        }
                        if (!requestAccepted) {
                            throw ProtocolViolationException("Channel request is invalid for channel $recipientChannel lifecycle")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_SUCCESS -> {
                        val msg = parseBody<SshMsgChannelSuccess>(packet)
                        requireAccepted(stateMachine.receiveChannelSuccess(msg.recipientChannel().toInt()), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_CHANNEL_FAILURE -> {
                        val msg = parseBody<SshMsgChannelFailure>(packet)
                        requireAccepted(stateMachine.receiveChannelFailure(msg.recipientChannel().toInt()), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_USERAUTH_SUCCESS -> {
                        requireAccepted(stateMachine.authenticationSuccess(), msgType)
                        val ch = authResultChannel
                        if (ch != null) {
                            ch.trySend(InternalAuthResult.Success)
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_USERAUTH_FAILURE -> {
                        val ch = authResultChannel
                        val msg = parseBody<SshMsgUserauthFailure>(packet)
                        requireAccepted(stateMachine.authenticationFailure(), msgType)
                        if (ch != null) {
                            val methods = msg.validAuthentications().entries().data().toSet()
                            val partial = msg.partialSuccess() != 0
                            ch.trySend(InternalAuthResult.Failure(methods, partial))
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_USERAUTH_BANNER -> {
                        val msg = parseBody<SshMsgUserauthBanner>(packet)
                        requireAccepted(stateMachine.receiveUserauthBanner(msg), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_USERAUTH_METHOD_SPECIFIC_60 -> {
                        requireAccepted(stateMachine.authorizeAuthenticationPacket(), msgType)
                        val ch = authResultChannel
                        if (ch != null && currentAuthMethod is AuthMethod.PublicKey) {
                            val msg = parseBody<SshMsgUserauthPkOk>(packet)
                            ch.trySend(
                                InternalAuthResult.PkOk(
                                    msg.publicKeyAlgorithmName().value(),
                                    msg.publicKeyBlob().data(),
                                ),
                            )
                        } else if (ch != null && currentAuthMethod is AuthMethod.KeyboardInteractive) {
                            val msg = parseBody<SshMsgUserauthInfoRequest>(packet)
                            val name = String(msg.name().data(), Charsets.UTF_8)
                            val instruction = String(msg.instruction().data(), Charsets.UTF_8)
                            val prompts = msg.prompts().map { prompt ->
                                KeyboardInteractiveCallback.Prompt(
                                    text = String(prompt.prompt().data(), Charsets.UTF_8),
                                    echo = prompt.echo() != 0,
                                )
                            }
                            ch.trySend(InternalAuthResult.InfoRequest(name, instruction, prompts))
                        } else {
                            val msg = parseBody<SshMsgUserauthInfoRequest>(packet)
                            requireAccepted(stateMachine.receiveUserauthInfoRequest(msg), msgType)
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_REQUEST_SUCCESS -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        val rawBody = packet._raw_body()
                        if (!pendingGlobalRequest.complete(rawBody)) {
                            throw ProtocolViolationException("Received SSH_MSG_REQUEST_SUCCESS with no pending global request")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_REQUEST_FAILURE -> {
                        requireAccepted(stateMachine.authorizeAuthenticatedPacket(), msgType)
                        if (!pendingGlobalRequest.complete(null)) {
                            throw ProtocolViolationException("Received SSH_MSG_REQUEST_FAILURE with no pending global request")
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_DISCONNECT -> {
                        val msg = parseBody<SshMsgDisconnect>(packet)
                        logger.info("Received SSH_MSG_DISCONNECT from server: reason=${msg.reasonCode()}, description=${msg.description().value()}")
                        requireAccepted(stateMachine.disconnect(), msgType)
                    }

                    SshEnums.MessageType.SSH_MSG_EXT_INFO -> {
                        requireAccepted(stateMachine.authorizeExtInfo(), msgType)
                        processServerExtInfo(parseBody(packet))
                    }

                    SshEnums.MessageType.SSH_MSG_PING -> {
                        requireAccepted(stateMachine.authorizeConnectionPacket(), msgType)
                        val msg = parseBody<SshMsgPing>(packet)
                        val pongSend: suspend () -> Unit = {
                            val pong = SshMsgPong()
                            pong.setData(createByteString(msg.data().data()))
                            pong._check()
                            writePacket(SshEnums.MessageType.SSH_MSG_PONG.id().toInt(), pong.toByteArray())
                        }
                        val sendNow = withContext(stateMachineDispatcher) {
                            if (isRekeying) {
                                pendingPingQueue.addLast(pongSend)
                                false
                            } else {
                                true
                            }
                        }
                        if (sendNow) {
                            pongSend()
                        }
                    }

                    SshEnums.MessageType.SSH_MSG_PONG -> {
                        requireAccepted(stateMachine.authorizeConnectionPacket(), msgType)
                        val msg = parseBody<SshMsgPong>(packet)
                        val seqBytes = msg.data().data()
                        if (seqBytes.size == 8) {
                            val seq = ByteBuffer.wrap(seqBytes).getLong()
                            withContext(stateMachineDispatcher) {
                                val pending = pendingPings.remove(seq)
                                if (pending != null) {
                                    val sentTimeNs = pending.sentTimeNs
                                    if (sentTimeNs != null) {
                                        pending.deferred.complete(PingResult.Success(System.nanoTime() - sentTimeNs))
                                    } else {
                                        pendingPings[seq] = pending
                                        logger.warn("Received SSH_MSG_PONG before ping send timestamp was recorded: $seq")
                                    }
                                } else {
                                    logger.debug("Ignoring SSH_MSG_PONG with no pending latency probe: $seq")
                                }
                            }
                        } else {
                            logger.trace("Ignoring opaque SSH_MSG_PONG payload (${seqBytes.size} bytes)")
                        }
                    }

                    else -> {
                        // KEX-specific messages 30-49 are not in MessageType enum.
                        // Disambiguate by negotiated KEX type since ECDH reply, DH reply,
                        // and DH-GEX group all share message ID 31.
                        val msgId = messageNumber
                        val rawBody = byteArrayOf(messageNumber.toByte()) + packet._raw_body()
                        val kexEntry = negotiatedKex?.let { KexEntry.fromSshName(it) }
                        when {
                            kexEntry?.type == KexType.ECDH &&
                                msgId == SshEnums.KexEcdh.SSH_MSG_KEX_ECDH_REPLY.id().toInt() -> {
                                val stream = ByteBufferKaitaiStream(rawBody)
                                val ecdhPayload = KexEcdhPayload(stream)
                                ecdhPayload._read()
                                val ecdhReply = ecdhPayload.body() as SshMsgKexEcdhReply
                                requireAccepted(stateMachine.receiveKexEcdhReply(ecdhReply), msgType)
                            }

                            kexEntry?.type == KexType.DH &&
                                msgId == SshEnums.KexDh.SSH_MSG_KEXDH_REPLY.id().toInt() -> {
                                val stream = ByteBufferKaitaiStream(rawBody)
                                val kexdhPayload = KexdhPayload(stream)
                                kexdhPayload._read()
                                val dhReply = kexdhPayload.body() as SshMsgKexdhReply
                                requireAccepted(stateMachine.receiveKexDhReply(dhReply), msgType)
                            }

                            kexEntry?.type == KexType.DH_GEX &&
                                msgId == SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_GROUP.id().toInt() -> {
                                val stream = ByteBufferKaitaiStream(rawBody)
                                val payload = KexDhGexPayload(stream)
                                payload._read()
                                val group = payload.body() as SshMsgKexDhGexGroup
                                dhGexGroup = group
                                requireAccepted(stateMachine.receiveKexDhGexGroup(group), msgType)
                            }

                            kexEntry?.type == KexType.DH_GEX &&
                                msgId == SshEnums.KexDhGex.SSH_MSG_KEX_DH_GEX_REPLY.id().toInt() -> {
                                val stream = ByteBufferKaitaiStream(rawBody)
                                val replyPayload = KexDhGexPayload(stream)
                                replyPayload._read()
                                val reply = replyPayload.body() as SshMsgKexDhGexReply
                                requireAccepted(stateMachine.receiveKexDhGexReply(reply), msgType)
                            }

                            else -> {
                                if (msgId in 30..49) {
                                    val description =
                                        "Unexpected key-exchange packet ${packet.messageType()} for negotiated algorithm $negotiatedKex"
                                    if (stateMachine.isStrictKexEnabled() && !isRekeying) {
                                        throw ProtocolViolationException(description)
                                    }
                                    logger.debug("$description; sending SSH_MSG_UNIMPLEMENTED")
                                    sendUnimplemented(packetSequenceNumber)
                                } else {
                                    logger.debug("Sending SSH_MSG_UNIMPLEMENTED for packet ${packet.messageType()}")
                                    sendUnimplemented(packetSequenceNumber)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Helper methods for SSH protocol encoding

    private inline fun <reified T : KaitaiStruct.ReadWrite> parseBody(packet: UnencryptedPacket.UnencryptedPayload): T {
        val rawBody = packet._raw_body()
        val stream = ByteBufferKaitaiStream(rawBody)
        val msg = T::class.java.getConstructor(KaitaiStream::class.java).newInstance(stream)
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
            msg.toByteArray(),
        )
    }

    /**
     * Sends a chaff SSH_MSG_PING packet sized to match a minimal SSH_MSG_CHANNEL_DATA frame
     * (4-byte channel ID + 4-byte length + 1-byte data = 9 bytes payload). Used for keystroke
     * timing obfuscation in interactive sessions.
     */
    internal suspend fun sendChaff() {
        if (!serverSupportsPing || isRekeying) return
        // SSH string encoding adds a 4-byte length, so 5 data bytes produce a 9-byte ping body.
        val payload = "PING!".encodeToByteArray()
        val ping = SshMsgPing()
        ping.setData(createByteString(payload))
        ping._check()
        writePacket(SshEnums.MessageType.SSH_MSG_PING.id().toInt(), ping.toByteArray())
    }

    internal suspend fun sendWindowAdjust(recipientChannel: Int, bytesToAdd: Int) {
        val msg = SshMsgChannelWindowAdjust().apply {
            setRecipientChannel(recipientChannel.toLong())
            setBytesToAdd(bytesToAdd.toLong())
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_WINDOW_ADJUST.id().toInt(),
            msg.toByteArray(),
        )
    }

    internal suspend fun sendChannelEof(recipientChannel: Int) {
        val msg = SshMsgChannelEof().apply {
            setRecipientChannel(recipientChannel.toLong())
            _check()
        }

        writePacket(
            SshEnums.MessageType.SSH_MSG_CHANNEL_EOF.id().toInt(),
            msg.toByteArray(),
        )
    }

    internal suspend fun notifyChannelClosed(localChannelNumber: Int) {
        val entry = channelRegistry.findByLocalRecipient(localChannelNumber)
        val wasSession = entry is SshChannelRegistry.Entry.Established.Session
        channelRegistry.unregister(localChannelNumber)
        if (entry is SshChannelRegistry.Entry.Established.Forwarding) {
            unregisterForwardingChannel(entry.channel)
        }

        val snapshot = channelRegistry.snapshot()
        val allClosed = snapshot.none { it is SshChannelRegistry.Entry.Pending } &&
            snapshot.filterIsInstance<SshChannelRegistry.Entry.Established>().all { !it.isOpen }
        val hasSession = snapshot.any { it.kind == SshChannelRegistry.Kind.SESSION }

        if (autoDisconnectOnLastChannelClose && allClosed && (hasSession || wasSession)) {
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
                msg.toByteArray(),
            )
        } catch (e: Exception) {
            logger.debug("Failed to send disconnect", e)
        }
        _disconnectedFlow.tryEmit(null)
        closeTransport()
    }

    private suspend fun sendProtocolError(description: String) {
        val msg = SshMsgDisconnect().apply {
            setReasonCode(SshEnums.DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR)
            setDescription(createUtf8String(description))
            setLanguage(createAsciiString(""))
            _check()
        }
        writePacket(
            SshEnums.MessageType.SSH_MSG_DISCONNECT.id().toInt(),
            msg.toByteArray(),
        )
    }

    private suspend fun sendUnimplemented(packetSequenceNumber: Long) {
        val msg = SshMsgUnimplemented().apply {
            setPacketSequence(packetSequenceNumber and 0xffff_ffffL)
            _check()
        }
        writePacket(
            SshEnums.MessageType.SSH_MSG_UNIMPLEMENTED.id().toInt(),
            msg.toByteArray(),
        )
    }

    private fun startPacketLoop() {
        if (packetLoopJob != null) return
        packetLoopJob = connectionScope.launch {
            var loopException: Exception? = null
            try {
                while (isActive) {
                    logger.debug("Packet loop: waiting for next packet")
                    inboundPacketController.processNextPacket()
                    if (!isRekeying && stateMachine.isPostAuthenticated() && (
                            packetIO.bytesSentOnWire >= rekeyBytesLimit ||
                                packetIO.bytesReceivedOnWire >= rekeyBytesLimit
                            )
                    ) {
                        dispatchCommand("ByteLimitRekey") { requestRekey() }
                    }
                }
            } catch (_: CancellationException) {
                logger.debug("Packet loop cancelled")
            } catch (e: Exception) {
                if (e is ProtocolViolationException) {
                    try {
                        if (!e.responseSent) {
                            sendProtocolError(e.message ?: "Unexpected SSH packet")
                        }
                    } catch (sendFailure: Exception) {
                        logger.debug("Failed to send protocol-error disconnect", sendFailure)
                    } finally {
                        isRekeying = false
                        authRequestPending = false
                        closeTransport()
                    }
                }
                val packetFailure = e.kaitaiParseFailureOrNull()
                val loopFailure = when {
                    e is SshException -> e
                    packetFailure != null -> TransportException("Malformed SSH packet", packetFailure)
                    else -> e
                }
                pendingConnect?.completeExceptionally(loopFailure)
                pendingConnect = null
                val allClosed = channelRegistry.establishedSnapshot().all { !it.isOpen }
                if (allClosed) {
                    logger.debug("Packet loop ended (all channels closed)")
                } else {
                    logger.warn("Packet loop ended unexpectedly", loopFailure)
                }
                loopException = loopFailure
            } finally {
                val loopError = loopException ?: Exception("Packet loop terminated")
                channelRegistry.disconnectAll(loopError)
                withContext(stateMachineDispatcher) {
                    pendingAuth.completeExceptionally(loopError)
                    pendingChannelRequests.values.forEach { it.completeExceptionally(loopError) }
                    pendingChannelRequests.clear()
                    pendingGlobalRequest.completeExceptionally(loopError)

                    for ((_, pending) in pendingPings) {
                        pending.deferred.complete(PingResult.Failure(loopError))
                    }
                    pendingPings.clear()
                    pendingPingQueue.clear()
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
        val lifecycle = SshChannelStateMachine(SshChannelState.OPENING)
        try {
            withContext(stateMachineDispatcher) {
                channelRegistry.registerPendingSession(localChannelNumber, deferred, lifecycle)
                check(
                    stateMachine.openChannel(
                        "session",
                        localChannelNumber,
                        initialWindowSize,
                        maxPacketSize,
                    ),
                )
            }
        } catch (failure: Throwable) {
            channelRegistry.removePendingSessionIf(localChannelNumber, deferred)?.lifecycle?.disconnect {}
            throw failure
        }

        val confirmationMsg = try {
            deferred.await()
        } catch (failure: Throwable) {
            channelRegistry.removePendingSessionIf(localChannelNumber, deferred)?.lifecycle?.disconnect {}
            throw failure
        } ?: return null

        val remoteChannelNumber = confirmationMsg.senderChannel().toInt()
        val remoteWindow = confirmationMsg.initialWindowSize()
        val remoteMaxPacketSize = boundRemotePacketSize(confirmationMsg.maximumPacketSize())
        if (remoteMaxPacketSize == null) {
            logger.warn("Rejecting session channel confirmation with invalid maximum packet size: ${confirmationMsg.maximumPacketSize()}")
            channelRegistry.removePendingSessionIf(localChannelNumber, deferred)
            lifecycle.sendClose { sendChannelClose(remoteChannelNumber) }
            return null
        }
        logger.info("Channel opened: local=$localChannelNumber, remote=$remoteChannelNumber, remoteWindow=$remoteWindow")

        val channel = SessionChannel(
            this,
            connectionScope,
            localChannelNumber,
            remoteChannelNumber,
            remoteMaxPacketSize,
            remoteWindowSizeInitial = remoteWindow,
            initialWindowSize = initialWindowSize,
            canSendChaff = serverSupportsPing,
            obscureKeystrokeTimingIntervalMs = obscureKeystrokeTimingIntervalMs,
            lifecycle = lifecycle,
        )
        val pending = channelRegistry.findPendingSession(localChannelNumber)
            ?: error("Pending session channel $localChannelNumber disappeared before promotion")
        channelRegistry.promote(pending, channel)
        logger.debug("Session channel registered: local=$localChannelNumber, remote=$remoteChannelNumber")

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
    internal suspend fun beginChannelRequest(
        recipientChannel: Int,
        requestType: String,
        wantReply: Boolean,
        configureRequest: (SshMsgChannelRequest) -> Unit,
    ): CompletableDeferred<Boolean>? {
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
                val remoteEntry = channelRegistry.findByRemoteRecipient(recipientChannel)
                val localChannelNumber = (remoteEntry as? SshChannelRegistry.Entry.Established.Session)?.localChannelNumber
                    ?: throw IllegalStateException("No session channel has remote channel number $recipientChannel")
                check(pendingChannelRequests.put(localChannelNumber, deferred) == null) {
                    "Channel $localChannelNumber already has a pending request"
                }
            }
            check(
                stateMachine.sendChannelRequest(
                    recipientChannel,
                    requestType,
                    wantReply,
                    msg,
                ),
            )
        }

        return deferred
    }

    internal suspend fun sendChannelRequest(
        recipientChannel: Int,
        requestType: String,
        wantReply: Boolean,
        configureRequest: (SshMsgChannelRequest) -> Unit,
    ): Boolean {
        val deferred = beginChannelRequest(recipientChannel, requestType, wantReply, configureRequest) ?: return true
        return try {
            deferred.await()
        } finally {
            finishChannelRequest(deferred)
        }
    }

    internal suspend fun finishChannelRequest(deferred: CompletableDeferred<Boolean>) {
        withContext(stateMachineDispatcher) {
            pendingChannelRequests.entries.removeIf { it.value === deferred }
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
            msg.toByteArray(),
        )
    }

    internal suspend fun ping(): PingResult {
        if (!serverSupportsPing) return PingResult.NotSupported

        val seq = pingSequence.getAndIncrement()
        val data = ByteBuffer.allocate(8).putLong(seq).array()
        val deferred = CompletableDeferred<PingResult>()

        val send: suspend () -> Unit = send@{
            try {
                val current = pendingPings[seq] ?: return@send
                val ping = SshMsgPing()
                ping.setData(createByteString(current.payload))
                ping._check()

                outboundPacketController.writePacket(
                    SshEnums.MessageType.SSH_MSG_PING.id().toInt(),
                    ping.toByteArray(),
                    beforeWrite = {
                        pendingPings[seq] = current.copy(sentTimeNs = System.nanoTime())
                    },
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                withContext(stateMachineDispatcher) {
                    if (pendingPings.remove(seq) != null) {
                        deferred.complete(PingResult.Failure(e))
                    }
                }
            }
        }

        withContext(stateMachineDispatcher) {
            pendingPings[seq] = PendingPing(deferred, data)
            if (isRekeying) {
                pendingPingQueue.addLast(send)
            } else {
                send()
            }
        }

        return try {
            deferred.await()
        } finally {
            withContext(NonCancellable) {
                withContext(stateMachineDispatcher) {
                    pendingPings.remove(seq)
                }
            }
        }
    }

    internal val connectionInfo: ConnectionInfo?
        get() {
            val kex = negotiatedKex ?: return null
            val hostKey = negotiatedHostKeyAlgorithm ?: return null
            val encC2S = negotiatedEncryptionC2S ?: return null
            val encS2C = negotiatedEncryptionS2C ?: return null
            return ConnectionInfo(
                kexAlgorithm = kex,
                serverHostKeyAlgorithm = hostKey,
                encryptionAlgorithmC2S = encC2S,
                encryptionAlgorithmS2C = encS2C,
                macAlgorithmC2S = negotiatedMacC2S,
                macAlgorithmS2C = negotiatedMacS2C,
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

internal fun keyBlobAlgorithmName(publicKeyBlob: ByteArray): String? {
    if (publicKeyBlob.size < 4) return null
    val stream = ByteBufferKaitaiStream(publicKeyBlob)
    val len = stream.readU4be()
    if (len <= 0 || len > publicKeyBlob.size - 4) return null
    return String(stream.readBytes(len), Charsets.US_ASCII)
}
