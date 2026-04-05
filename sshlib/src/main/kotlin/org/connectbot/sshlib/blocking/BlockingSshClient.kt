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

package org.connectbot.sshlib.blocking

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.AgentProvider
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PortForwarder
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.Socks5Authenticator
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.StreamForwarder
import org.connectbot.sshlib.transport.TransportFactory
import java.net.InetSocketAddress

/**
 * Blocking wrapper for SshClient for Java compatibility.
 *
 * This class wraps the async [SshClient] with blocking calls using
 * [runBlocking]. For Kotlin code, prefer using [SshClient] directly
 * with coroutines.
 *
 * Usage from Java:
 * ```java
 * BlockingSshClient client = new BlockingSshClient("example.com", 22, myHostKeyVerifier);
 * try {
 *     client.connect();
 *     client.authenticatePassword("user", "password");
 *     SshSession session = client.openSession();
 *     // ...
 *     session.close();
 *     client.disconnect();
 * } catch (SshException e) {
 *     // handle connection or auth failure
 * }
 * ```
 *
 * With custom transport:
 * ```java
 * BlockingSshClient client = new BlockingSshClient(myTransportFactory);
 * ```
 */
class BlockingSshClient internal constructor(
    private val client: SshClient,
) {
    /**
     * Create a blocking SSH client for TCP connection.
     */
    @JvmOverloads
    constructor(
        host: String,
        port: Int = 22,
        hostKeyVerifier: HostKeyVerifier,
        clientVersion: String = "SSH-2.0-CBSSH_1.0",
    ) : this(
        SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = hostKeyVerifier
            this.clientVersion = clientVersion
        },
    )

    /**
     * Create a blocking SSH client from configuration.
     */
    constructor(config: SshClientConfig) : this(SshClient(config))

    /**
     * Create a blocking SSH client with custom transport factory.
     */
    constructor(
        transportFactory: TransportFactory,
        clientVersion: String = "SSH-2.0-CBSSH_1.0",
    ) : this(SshClient(transportFactory, clientVersion))

    /**
     * Connect to the SSH server and perform key exchange.
     *
     * @throws SshException if the connection fails
     */
    @Throws(SshException::class)
    fun connect() {
        when (val result = runBlocking { client.connect() }) {
            is ConnectResult.Success -> Unit
            is ConnectResult.HostKeyRejected -> throw SshException("Host key rejected for key: ${result.key.type}")
            is ConnectResult.AlgorithmMismatch -> throw SshException(result.message)
            is ConnectResult.TransportError -> throw SshException("Transport error: ${result.cause}", result.cause)
            is ConnectResult.ProtocolError -> throw SshException(result.message, result.cause)
        }
    }

    /**
     * Authenticate using password authentication.
     *
     * @param username SSH username
     * @param password SSH password
     * @throws SshException if authentication fails or an error occurs
     */
    @Throws(SshException::class)
    fun authenticatePassword(username: String, password: String) {
        when (val result = runBlocking { client.authenticatePassword(username, password) }) {
            is AuthResult.Success -> Unit
            is AuthResult.Failure -> throw SshException("Authentication failed; allowed methods: ${result.allowedMethods}")
            is AuthResult.Error -> throw SshException(result.message, result.cause)
        }
    }

    /**
     * Authenticate using the strategy-based [AuthHandler] flow.
     *
     * @param username SSH username
     * @param handler Callback handler providing authentication materials
     * @throws SshException if authentication fails or an error occurs
     */
    @Throws(SshException::class)
    fun authenticate(username: String, handler: AuthHandler) {
        when (val result = runBlocking { client.authenticate(username, handler) }) {
            is AuthResult.Success -> Unit
            is AuthResult.Failure -> throw SshException("Authentication failed; allowed methods: ${result.allowedMethods}")
            is AuthResult.Error -> throw SshException(result.message, result.cause)
        }
    }

    /**
     * Authenticate using keyboard-interactive authentication (RFC 4256).
     *
     * @param username SSH username
     * @param callback Receives prompts from the server and provides responses
     * @throws SshException if authentication fails or an error occurs
     */
    @Throws(SshException::class)
    fun authenticateKeyboardInteractive(username: String, callback: KeyboardInteractiveCallback) {
        when (val result = runBlocking { client.authenticateKeyboardInteractive(username, callback) }) {
            is AuthResult.Success -> Unit
            is AuthResult.Failure -> throw SshException("Authentication failed; allowed methods: ${result.allowedMethods}")
            is AuthResult.Error -> throw SshException(result.message, result.cause)
        }
    }

    /**
     * Authenticate using public key authentication (RFC 4252 §7).
     *
     * @param username SSH username
     * @param privateKeyData Private key file contents
     * @param passphrase Passphrase for encrypted keys, or null
     * @throws SshException if authentication fails or an error occurs
     */
    @JvmOverloads
    @Throws(SshException::class)
    fun authenticatePublicKey(
        username: String,
        privateKeyData: ByteArray,
        passphrase: String? = null,
    ) {
        when (val result = runBlocking { client.authenticatePublicKey(username, privateKeyData, passphrase) }) {
            is AuthResult.Success -> Unit
            is AuthResult.Failure -> throw SshException("Authentication failed; allowed methods: ${result.allowedMethods}")
            is AuthResult.Error -> throw SshException(result.message, result.cause)
        }
    }

    /**
     * Authenticate using public key authentication (RFC 4252 §7).
     *
     * @param username SSH username
     * @param privateKeyData Private key file contents as a string
     * @param passphrase Passphrase for encrypted keys, or null
     * @throws SshException if authentication fails or an error occurs
     */
    @JvmOverloads
    @Throws(SshException::class)
    fun authenticatePublicKey(
        username: String,
        privateKeyData: String,
        passphrase: String? = null,
    ) {
        when (val result = runBlocking { client.authenticatePublicKey(username, privateKeyData, passphrase) }) {
            is AuthResult.Success -> Unit
            is AuthResult.Failure -> throw SshException("Authentication failed; allowed methods: ${result.allowedMethods}")
            is AuthResult.Error -> throw SshException(result.message, result.cause)
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
        client.enableAgentForwarding(provider)
    }

    /**
     * Emits when the connection drops unexpectedly.
     *
     * @see SshClient.disconnectedFlow
     */
    val disconnectedFlow: SharedFlow<Throwable?>
        get() = client.disconnectedFlow

    /**
     * Check if connected and authenticated.
     */
    val isAuthenticated: Boolean
        get() = client.isAuthenticated

    /**
     * Open a session channel (RFC 4254 section 6.1).
     *
     * @return SshSession instance if successful, null otherwise
     */
    fun openSession(): SshSession? = runBlocking { client.openSession() }

    /**
     * Open an SFTP session for file transfer (blocking wrapper).
     */
    fun openSftp(): SftpClient? = runBlocking { client.openSftp() }

    /**
     * Start local port forwarding.
     */
    fun localPortForward(
        bindAddress: InetSocketAddress,
        remoteHost: String,
        remotePort: Int,
    ): PortForwarder? = runBlocking { client.localPortForward(bindAddress, remoteHost, remotePort) }

    /**
     * Start local port forwarding bound to localhost.
     */
    fun localPortForward(
        bindPort: Int,
        remoteHost: String,
        remotePort: Int,
    ): PortForwarder? = runBlocking { client.localPortForward(bindPort, remoteHost, remotePort) }

    /**
     * Start remote port forwarding.
     */
    fun remotePortForward(
        remoteBindAddress: String,
        remoteBindPort: Int,
        localHost: String,
        localPort: Int,
    ): PortForwarder? = runBlocking { client.remotePortForward(remoteBindAddress, remoteBindPort, localHost, localPort) }

    /**
     * Start dynamic (SOCKS5) port forwarding.
     */
    @JvmOverloads
    fun dynamicPortForward(
        bindAddress: InetSocketAddress,
        authenticator: Socks5Authenticator? = null,
    ): PortForwarder? = runBlocking { client.dynamicPortForward(bindAddress, authenticator) }

    /**
     * Start dynamic (SOCKS5) port forwarding bound to localhost.
     */
    @JvmOverloads
    fun dynamicPortForward(
        bindPort: Int,
        authenticator: Socks5Authenticator? = null,
    ): PortForwarder? = runBlocking { client.dynamicPortForward(bindPort, authenticator) }

    /**
     * Forward Ktor byte channels through an SSH direct-tcpip channel.
     */
    @JvmOverloads
    fun forwardStream(
        readChannel: ByteReadChannel,
        writeChannel: ByteWriteChannel,
        remoteHost: String,
        remotePort: Int,
        originAddr: String = "127.0.0.1",
        originPort: Int = 0,
    ): StreamForwarder? = runBlocking {
        client.forwardStream(readChannel, writeChannel, remoteHost, remotePort, originAddr, originPort)
    }

    /**
     * Create a [org.connectbot.sshlib.transport.TransportFactory] that tunnels through this SSH connection.
     */
    @JvmOverloads
    fun openDirectTcpipTransport(
        remoteHost: String,
        remotePort: Int,
        originAddr: String = "127.0.0.1",
        originPort: Int = 0,
    ): TransportFactory? = client.openDirectTcpipTransport(remoteHost, remotePort, originAddr, originPort)

    /**
     * Disconnect from the SSH server.
     */
    fun disconnect() = runBlocking { client.disconnect() }
}
