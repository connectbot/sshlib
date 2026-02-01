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
            clientVersion: String = "SSH-2.0-SshProtoClient_1.0"
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
            clientVersion: String = "SSH-2.0-SshProtoClient_1.0"
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
