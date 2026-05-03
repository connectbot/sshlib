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

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import org.connectbot.sshlib.PingResult
import org.connectbot.sshlib.client.DynamicPortForwarder
import org.connectbot.sshlib.client.LocalPortForwarder
import org.connectbot.sshlib.client.RemotePortForwarder
import org.connectbot.sshlib.client.SshConnection
import org.connectbot.sshlib.client.sftp.SftpClientImpl
import org.connectbot.sshlib.crypto.PrivateKeyReader
import org.connectbot.sshlib.transport.ForwardingChannelTransport
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportFactory
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress

/**
 * High-level async SSH client API.
 *
 * This is the main entry point for establishing SSH connections. All methods
 * are suspend functions for use with Kotlin coroutines.
 *
 * Usage with TCP (default):
 * ```kotlin
 * val client = SshClient("example.com")
 * if (client.connect() is ConnectResult.Success) {
 *     if (client.authenticatePassword("user", "password") is AuthResult.Success) {
 *         val session = client.openSession()
 *         session?.requestPty()
 *         session?.requestShell()
 *         // read/write
 *         session?.close()
 *     }
 *     client.disconnect()
 * }
 * ```
 *
 * Usage with custom transport:
 * ```kotlin
 * val config = SshClientConfig {
 *     transportFactory = MyCustomTransportFactory()
 * }
 * val client = SshClient(config)
 * client.connect()
 * // ...
 * ```
 *
 * For blocking Java compatibility, use [org.connectbot.sshlib.blocking.BlockingSshClient].
 */
class SshClient private constructor(
    private val config: SshClientConfig,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(SshClient::class.java)

        /**
         * Create an SshClient for TCP connection to the specified host.
         *
         * @param host SSH server hostname
         * @param port SSH server port (default 22)
         * @param clientVersion Client version string for the SSH handshake
         */
        operator fun invoke(
            host: String,
            port: Int = 22,
            clientVersion: String = "SSH-2.0-CBSSH_1.0",
        ): SshClient {
            val config = SshClientConfig {
                this.host = host
                this.port = port
                this.clientVersion = clientVersion
            }
            return SshClient(config)
        }

        /**
         * Create an SshClient from a configuration.
         */
        operator fun invoke(config: SshClientConfig): SshClient = SshClient(config)

        /**
         * Create an SshClient with a custom transport factory.
         *
         * @param transportFactory Factory to create the transport
         * @param clientVersion Client version string for the SSH handshake
         */
        operator fun invoke(
            transportFactory: TransportFactory,
            clientVersion: String = "SSH-2.0-CBSSH_1.0",
        ): SshClient {
            val config = SshClientConfig {
                this.transportFactory = transportFactory
                this.clientVersion = clientVersion
            }
            return SshClient(config)
        }
    }

    private var transport: Transport? = null
    private var connection: SshConnection? = null
    private var authenticated = false
    private val forwardingScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var disconnectForwardJob: Job? = null

    private val _disconnectedFlow = MutableSharedFlow<Throwable?>(extraBufferCapacity = 1)

    /**
     * Emits when the connection drops unexpectedly.
     *
     * The value is the [Throwable] that caused the disconnection (e.g., transport error),
     * or `null` if the server sent a clean SSH_MSG_DISCONNECT.
     *
     * This flow does **not** emit when [disconnect] is called by the caller.
     */
    val disconnectedFlow: SharedFlow<Throwable?> = _disconnectedFlow.asSharedFlow()

    /**
     * Connect to the SSH server and perform key exchange.
     *
     * @return [ConnectResult] indicating success or failure
     */
    suspend fun connect(): ConnectResult = try {
        logger.info("Connecting via transport factory")

        val newTransport = config.transportFactory.create()
        transport = newTransport

        val sshConnection = SshConnection(
            transport = newTransport,
            clientVersion = config.clientVersion,
            hostKeyVerifier = config.hostKeyVerifier,
            kexAlgorithms = config.kexAlgorithms,
            hostKeyAlgorithms = config.hostKeyAlgorithms,
            encryptionAlgorithms = config.encryptionAlgorithms,
            macAlgorithms = config.macAlgorithms,
            compressionAlgorithms = config.compressionAlgorithms,
            preferPasswordAuth = config.preferPasswordAuth,
            rekeyIntervalMs = config.rekeyIntervalMs,
            rekeyBytesLimit = config.rekeyBytesLimit,
            obscureKeystrokeTimingIntervalMs = config.obscureKeystrokeTimingIntervalMs,
        )
        val result = sshConnection.connect()

        if (result is ConnectResult.Success) {
            connection = sshConnection
            disconnectForwardJob = forwardingScope.launch {
                sshConnection.disconnectedFlow.collect { cause ->
                    _disconnectedFlow.tryEmit(cause)
                }
            }
            logger.info("Successfully connected")
        } else {
            disconnect()
            logger.error("Connection failed: $result")
        }

        result
    } catch (e: Exception) {
        logger.error("Connection failed", e)
        disconnect()
        ConnectResult.TransportError(e)
    }

    /**
     * Authenticate using password authentication.
     *
     * @param username SSH username
     * @param password SSH password
     * @return [AuthResult] indicating success or failure
     * @return [AuthResult.Error] if [connect] has not been called successfully
     */
    suspend fun authenticatePassword(username: String, password: String): AuthResult {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return AuthResult.Error("Not connected")
        }

        return try {
            logger.info("Authenticating as $username")
            val result = conn.authenticatePassword(username, password)

            if (result is AuthResult.Success) {
                authenticated = true
                logger.info("Authentication successful")
            } else {
                logger.warn("Authentication failed: $result")
            }

            result
        } catch (e: Exception) {
            logger.error("Authentication error", e)
            AuthResult.Error(e.message ?: "Authentication error", e)
        }
    }

    /**
     * Authenticate using keyboard-interactive authentication (RFC 4256).
     *
     * @param username SSH username
     * @param callback Receives prompts from the server and provides responses
     * @return [AuthResult] indicating success or failure
     * @return [AuthResult.Error] if [connect] has not been called successfully
     */
    suspend fun authenticateKeyboardInteractive(
        username: String,
        callback: KeyboardInteractiveCallback,
    ): AuthResult {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return AuthResult.Error("Not connected")
        }

        return try {
            logger.info("Authenticating as $username via keyboard-interactive")
            val result = conn.authenticateKeyboardInteractive(username, callback)

            if (result is AuthResult.Success) {
                authenticated = true
                logger.info("Keyboard-interactive authentication successful")
            } else {
                logger.warn("Keyboard-interactive authentication failed: $result")
            }

            result
        } catch (e: Exception) {
            logger.error("Keyboard-interactive authentication error", e)
            AuthResult.Error(e.message ?: "Keyboard-interactive error", e)
        }
    }

    /**
     * Authenticate using public key authentication (RFC 4252 §7).
     *
     * @param username SSH username
     * @param privateKeyData Private key file contents
     * @param passphrase Passphrase for encrypted keys, or null
     * @return [AuthResult] indicating success or failure
     * @return [AuthResult.Error] if [connect] has not been called successfully
     */
    suspend fun authenticatePublicKey(
        username: String,
        privateKeyData: ByteArray,
        passphrase: String? = null,
    ): AuthResult = authenticatePublicKey(username, String(privateKeyData, Charsets.UTF_8), passphrase)

    /**
     * Authenticate using public key authentication (RFC 4252 §7).
     *
     * @param username SSH username
     * @param privateKeyData Private key file contents as a string
     * @param passphrase Passphrase for encrypted keys, or null
     * @return [AuthResult] indicating success or failure
     * @return [AuthResult.Error] if [connect] has not been called successfully
     */
    suspend fun authenticatePublicKey(
        username: String,
        privateKeyData: String,
        passphrase: String? = null,
    ): AuthResult {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return AuthResult.Error("Not connected")
        }

        return try {
            logger.info("Authenticating as $username via public key")
            val privateKey = PrivateKeyReader.read(privateKeyData, passphrase)
            val result = conn.authenticatePublicKey(username, privateKey)

            if (result is AuthResult.Success) {
                authenticated = true
                logger.info("Public key authentication successful")
            } else {
                logger.warn("Public key authentication failed: $result")
            }

            result
        } catch (e: Exception) {
            logger.error("Public key authentication error", e)
            AuthResult.Error(e.message ?: "Public key authentication error", e)
        }
    }

    /**
     * Authenticate using the strategy-based [AuthHandler] flow.
     *
     * The library drives the authentication per RFC 4252, calling back into the
     * handler for materials. The flow is:
     * none → publickey probe → sign → keyboard-interactive → password.
     *
     * @param username SSH username
     * @param handler Callback handler providing authentication materials
     * @return [AuthResult] indicating success or failure
     * @return [AuthResult.Error] if [connect] has not been called successfully
     */
    suspend fun authenticate(username: String, handler: AuthHandler): AuthResult {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return AuthResult.Error("Not connected")
        }

        return try {
            logger.info("Authenticating as $username via auth handler")
            val result = conn.authenticate(username, handler)

            if (result is AuthResult.Success) {
                authenticated = true
                logger.info("Auth handler authentication successful")
            } else {
                logger.warn("Auth handler authentication failed: $result")
            }

            result
        } catch (e: Exception) {
            logger.error("Auth handler authentication error", e)
            AuthResult.Error(e.message ?: "Auth handler error", e)
        }
    }

    /**
     * Enable SSH agent forwarding with the provided agent.
     *
     * Must be called before opening sessions. When agent forwarding is enabled,
     * remote servers can request signatures from your agent provider.
     *
     * @param provider Agent implementation that handles signing requests
     */
    fun enableAgentForwarding(provider: AgentProvider) {
        connection?.enableAgentForwarding(provider)
    }

    /**
     * Check if the provided private key data is encrypted and requires a passphrase.
     *
     * @param privateKeyData Private key file contents
     * @return true if the key is encrypted
     */
    fun isPrivateKeyEncrypted(privateKeyData: ByteArray): Boolean = isPrivateKeyEncrypted(String(privateKeyData, Charsets.UTF_8))

    /**
     * Check if the provided private key data is encrypted and requires a passphrase.
     *
     * @param privateKeyData Private key file contents as a string
     * @return true if the key is encrypted
     */
    fun isPrivateKeyEncrypted(privateKeyData: String): Boolean = try {
        PrivateKeyReader.isEncrypted(privateKeyData)
    } catch (e: Exception) {
        logger.error("Failed to check if key is encrypted", e)
        false
    }

    /**
     * Check if connected and authenticated.
     */
    val isAuthenticated: Boolean
        get() = authenticated && connection != null && transport?.isConnected == true

    /**
     * Negotiated algorithm details for the current connection.
     *
     * Null before [connect] succeeds or after [disconnect].
     */
    val connectionInfo: ConnectionInfo?
        get() = connection?.connectionInfo

    /**
     * Open a session channel (RFC 4254 section 6.1).
     *
     * @return SshSession instance if successful, null otherwise
     */
    suspend fun openSession(): SshSession? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated - call connect() and authenticatePassword() first")
            return null
        }

        return try {
            logger.info("Opening session channel")
            conn.openSessionChannel()
        } catch (e: Exception) {
            logger.error("Failed to open session channel", e)
            null
        }
    }

    /**
     * Open an SFTP session for file transfer.
     *
     * Opens a new session channel, starts the "sftp" subsystem, and performs
     * SFTP version negotiation.
     *
     * @return [SftpResult.Success] with the client, or an error variant
     */
    suspend fun openSftp(): SftpResult<SftpClient> {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated - call connect() and authenticate first")
            return SftpResult.IoError(IllegalStateException("Not authenticated"))
        }

        return try {
            logger.info("Opening SFTP session")
            val session = conn.openSessionChannel()
                ?: return SftpResult.ProtocolError("Failed to open session channel for SFTP")
            if (!session.requestSubsystem("sftp")) {
                session.close()
                return SftpResult.ProtocolError("Server rejected SFTP subsystem request")
            }
            SftpClientImpl.create(session)
        } catch (e: Exception) {
            logger.error("Failed to open SFTP session", e)
            SftpResult.IoError(e)
        }
    }

    /**
     * Start local port forwarding (RFC 4254 section 7.2).
     *
     * Listens on [bindAddress] locally and forwards each connection through SSH
     * to [remoteHost]:[remotePort] on the remote side.
     *
     * @param bindAddress Local address to bind
     * @param remoteHost Remote host to connect to through SSH
     * @param remotePort Remote port to connect to through SSH
     * @return PortForwarder handle, or null if not authenticated
     */
    suspend fun localPortForward(
        bindAddress: InetSocketAddress,
        remoteHost: String,
        remotePort: Int,
    ): PortForwarder? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated")
            return null
        }

        return try {
            LocalPortForwarder.create(forwardingScope, conn, bindAddress, remoteHost, remotePort)
        } catch (e: Exception) {
            logger.error("Failed to start local port forwarding", e)
            null
        }
    }

    /**
     * Start local port forwarding bound to localhost.
     *
     * @param bindPort Local port to bind (0 for automatic)
     * @param remoteHost Remote host to connect to through SSH
     * @param remotePort Remote port to connect to through SSH
     * @return PortForwarder handle, or null if not authenticated
     */
    suspend fun localPortForward(
        bindPort: Int,
        remoteHost: String,
        remotePort: Int,
    ): PortForwarder? = localPortForward(InetSocketAddress("127.0.0.1", bindPort), remoteHost, remotePort)

    /**
     * Start remote port forwarding (RFC 4254 section 7.1).
     *
     * Asks the SSH server to listen on [remoteBindAddress]:[remoteBindPort] and
     * forwards each connection back to [localHost]:[localPort] on this machine.
     *
     * @param remoteBindAddress Address for the server to bind
     * @param remoteBindPort Port for the server to bind (0 for automatic)
     * @param localHost Local host to forward to
     * @param localPort Local port to forward to
     * @return PortForwarder handle, or null if the server rejected the request
     */
    suspend fun remotePortForward(
        remoteBindAddress: String,
        remoteBindPort: Int,
        localHost: String,
        localPort: Int,
    ): PortForwarder? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated")
            return null
        }

        return try {
            RemotePortForwarder.create(forwardingScope, conn, remoteBindAddress, remoteBindPort, localHost, localPort)
        } catch (e: Exception) {
            logger.error("Failed to start remote port forwarding", e)
            null
        }
    }

    /**
     * Start dynamic (SOCKS5) port forwarding.
     *
     * Listens on [bindAddress] locally as a SOCKS5 proxy. Each SOCKS5 CONNECT
     * request opens a direct-tcpip channel through SSH to the requested destination.
     *
     * @param bindAddress Local address to bind the SOCKS5 proxy
     * @param authenticator Optional SOCKS5 username/password authenticator
     * @return PortForwarder handle, or null if not authenticated
     */
    suspend fun dynamicPortForward(
        bindAddress: InetSocketAddress,
        authenticator: Socks5Authenticator? = null,
    ): PortForwarder? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated")
            return null
        }

        return try {
            DynamicPortForwarder.create(forwardingScope, conn, bindAddress, authenticator)
        } catch (e: Exception) {
            logger.error("Failed to start dynamic port forwarding", e)
            null
        }
    }

    /**
     * Start dynamic (SOCKS5) port forwarding bound to localhost.
     *
     * @param bindPort Local port to bind (0 for automatic)
     * @param authenticator Optional SOCKS5 username/password authenticator
     * @return PortForwarder handle, or null if not authenticated
     */
    suspend fun dynamicPortForward(
        bindPort: Int,
        authenticator: Socks5Authenticator? = null,
    ): PortForwarder? = dynamicPortForward(InetSocketAddress("127.0.0.1", bindPort), authenticator)

    /**
     * Forward a pair of streams through an SSH direct-tcpip channel.
     *
     * Opens a direct-tcpip channel to [remoteHost]:[remotePort] and copies data
     * bidirectionally between the provided Ktor channels and the SSH channel.
     *
     * @param readChannel Source of data to send through SSH
     * @param writeChannel Destination for data received from SSH
     * @param remoteHost Remote host to connect to through SSH
     * @param remotePort Remote port to connect to through SSH
     * @param originAddr Originator address reported to the server
     * @param originPort Originator port reported to the server
     * @return StreamForwarder handle, or null if the channel could not be opened
     */
    suspend fun forwardStream(
        readChannel: ByteReadChannel,
        writeChannel: ByteWriteChannel,
        remoteHost: String,
        remotePort: Int,
        originAddr: String = "127.0.0.1",
        originPort: Int = 0,
    ): StreamForwarder? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated")
            return null
        }

        return try {
            org.connectbot.sshlib.client.StreamForwarder.create(
                conn,
                readChannel,
                writeChannel,
                remoteHost,
                remotePort,
                originAddr,
                originPort,
            )
        } catch (e: Exception) {
            logger.error("Failed to start stream forwarding", e)
            null
        }
    }

    /**
     * Create a [TransportFactory] that tunnels through this SSH connection.
     *
     * Opens a direct-tcpip channel to [remoteHost]:[remotePort] and wraps it
     * as a [Transport], allowing a second [SshClient] to connect through this
     * connection without transiting the kernel network stack (jump host /
     * ProxyJump pattern).
     *
     * ```kotlin
     * val jump = SshClient("jump.example.com")
     * jump.connect()
     * jump.authenticatePassword("user", "pass")
     *
     * val targetConfig = SshClientConfig {
     *     transportFactory = jump.openDirectTcpipTransport("target.internal", 22)
     *     hostKeyVerifier = myVerifier
     * }
     * val target = SshClient(targetConfig)
     * target.connect()
     * ```
     *
     * @param remoteHost Host reachable from the SSH server to connect to
     * @param remotePort Port on the remote host
     * @param originAddr Originator address reported to the server
     * @param originPort Originator port reported to the server
     * @return TransportFactory for use in [SshClientConfig], or null if not authenticated
     */
    fun openDirectTcpipTransport(
        remoteHost: String,
        remotePort: Int,
        originAddr: String = "127.0.0.1",
        originPort: Int = 0,
    ): TransportFactory? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated")
            return null
        }

        return TransportFactory {
            val channel = conn.openDirectTcpipChannel(
                remoteHost,
                remotePort,
                originAddr,
                originPort,
            ) ?: throw SshException("Failed to open direct-tcpip channel to $remoteHost:$remotePort")
            ForwardingChannelTransport(channel)
        }
    }

    /**
     * Send an SSH ping to the server and return the round-trip time.
     *
     * Requires a prior successful [connect] and authentication. Returns
     * [PingResult.NotAuthenticated] if there is no active connection or
     * authentication has not completed, [PingResult.NotSupported] if the server
     * did not advertise `ping@openssh.com` support via SSH2_MSG_EXT_INFO, or
     * [PingResult.Failure] if the ping cannot be sent or the connection closes
     * before the server replies.
     *
     * @return [PingResult.Success] with round-trip nanoseconds, [PingResult.NotSupported],
     *   [PingResult.NotAuthenticated], or [PingResult.Failure]
     */
    suspend fun ping(): PingResult {
        val conn = connection ?: return PingResult.NotAuthenticated
        if (!authenticated) return PingResult.NotAuthenticated
        return conn.ping()
    }

    /**
     * Disconnect from the SSH server.
     */
    suspend fun disconnect() {
        logger.info("Disconnecting")

        disconnectForwardJob?.cancel()
        disconnectForwardJob = null

        connection?.close()
        connection = null

        transport?.close()
        transport = null

        authenticated = false
    }
}
