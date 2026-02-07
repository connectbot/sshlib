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

import org.connectbot.sshlib.client.SshConnection
import org.connectbot.sshlib.crypto.PrivateKeyReader
import org.connectbot.sshlib.transport.KtorTcpTransportFactory
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportFactory
import org.slf4j.LoggerFactory

/**
 * High-level async SSH client API.
 *
 * This is the main entry point for establishing SSH connections. All methods
 * are suspend functions for use with Kotlin coroutines.
 *
 * Usage with TCP (default):
 * ```kotlin
 * val client = SshClient("example.com")
 * client.connect()
 * if (client.authenticatePassword("user", "password")) {
 *     val session = client.openSession()
 *     session.requestPty()
 *     session.requestShell()
 *     // read/write
 *     session.close()
 * }
 * client.disconnect()
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
    private val config: SshClientConfig
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
            clientVersion: String = "SSH-2.0-CBSSH_1.0"
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
        operator fun invoke(config: SshClientConfig): SshClient {
            return SshClient(config)
        }

        /**
         * Create an SshClient with a custom transport factory.
         *
         * @param transportFactory Factory to create the transport
         * @param clientVersion Client version string for the SSH handshake
         */
        operator fun invoke(
            transportFactory: TransportFactory,
            clientVersion: String = "SSH-2.0-CBSSH_1.0"
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

    /**
     * Connect to the SSH server and perform key exchange.
     *
     * @return true if connection succeeded
     */
    suspend fun connect(): Boolean {
        try {
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
                macAlgorithms = config.macAlgorithms
            )
            val success = sshConnection.connect()

            if (success) {
                connection = sshConnection
                logger.info("Successfully connected")
            } else {
                disconnect()
                logger.error("Connection failed")
            }

            return success
        } catch (e: Exception) {
            logger.error("Connection failed", e)
            disconnect()
            return false
        }
    }

    /**
     * Authenticate using password authentication.
     *
     * @param username SSH username
     * @param password SSH password
     * @return true if authentication succeeded
     */
    suspend fun authenticatePassword(username: String, password: String): Boolean {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return false
        }

        return try {
            logger.info("Authenticating as $username")
            val success = conn.authenticatePassword(username, password)

            if (success) {
                authenticated = true
                logger.info("Authentication successful")
            } else {
                logger.warn("Authentication failed")
            }

            success
        } catch (e: Exception) {
            logger.error("Authentication error", e)
            false
        }
    }

    /**
     * Authenticate using keyboard-interactive authentication (RFC 4256).
     *
     * @param username SSH username
     * @param callback Receives prompts from the server and provides responses
     * @return true if authentication succeeded
     */
    suspend fun authenticateKeyboardInteractive(
        username: String,
        callback: KeyboardInteractiveCallback
    ): Boolean {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return false
        }

        return try {
            logger.info("Authenticating as $username via keyboard-interactive")
            val success = conn.authenticateKeyboardInteractive(username, callback)

            if (success) {
                authenticated = true
                logger.info("Keyboard-interactive authentication successful")
            } else {
                logger.warn("Keyboard-interactive authentication failed")
            }

            success
        } catch (e: Exception) {
            logger.error("Keyboard-interactive authentication error", e)
            false
        }
    }

    /**
     * Authenticate using public key authentication (RFC 4252 §7).
     *
     * @param username SSH username
     * @param privateKeyData Private key file contents
     * @param passphrase Passphrase for encrypted keys, or null
     * @return true if authentication succeeded
     */
    suspend fun authenticatePublicKey(
        username: String,
        privateKeyData: ByteArray,
        passphrase: String? = null
    ): Boolean {
        return authenticatePublicKey(username, String(privateKeyData, Charsets.UTF_8), passphrase)
    }

    /**
     * Authenticate using public key authentication (RFC 4252 §7).
     *
     * @param username SSH username
     * @param privateKeyData Private key file contents as a string
     * @param passphrase Passphrase for encrypted keys, or null
     * @return true if authentication succeeded
     */
    suspend fun authenticatePublicKey(
        username: String,
        privateKeyData: String,
        passphrase: String? = null
    ): Boolean {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return false
        }

        return try {
            logger.info("Authenticating as $username via public key")
            val privateKey = PrivateKeyReader.read(privateKeyData, passphrase)
            val success = conn.authenticatePublicKey(username, privateKey)

            if (success) {
                authenticated = true
                logger.info("Public key authentication successful")
            } else {
                logger.warn("Public key authentication failed")
            }

            success
        } catch (e: Exception) {
            logger.error("Public key authentication error", e)
            false
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
     * @return true if authentication succeeded
     */
    suspend fun authenticate(username: String, handler: AuthHandler): Boolean {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return false
        }

        return try {
            logger.info("Authenticating as $username via auth handler")
            val success = conn.authenticate(username, handler)

            if (success) {
                authenticated = true
                logger.info("Auth handler authentication successful")
            } else {
                logger.warn("Auth handler authentication failed")
            }

            success
        } catch (e: Exception) {
            logger.error("Auth handler authentication error", e)
            false
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
    fun isPrivateKeyEncrypted(privateKeyData: ByteArray): Boolean {
        return isPrivateKeyEncrypted(String(privateKeyData, Charsets.UTF_8))
    }

    /**
     * Check if the provided private key data is encrypted and requires a passphrase.
     *
     * @param privateKeyData Private key file contents as a string
     * @return true if the key is encrypted
     */
    fun isPrivateKeyEncrypted(privateKeyData: String): Boolean {
        return try {
            PrivateKeyReader.isEncrypted(privateKeyData)
        } catch (e: Exception) {
            logger.error("Failed to check if key is encrypted", e)
            false
        }
    }

    /**
     * Check if connected and authenticated.
     */
    val isAuthenticated: Boolean
        get() = authenticated && connection != null && transport?.isConnected == true

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
     * Disconnect from the SSH server.
     */
    suspend fun disconnect() {
        logger.info("Disconnecting")

        connection?.close()
        connection = null

        transport?.close()
        transport = null

        authenticated = false
    }
}
