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

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.transport.KtorTcpTransport
import org.slf4j.LoggerFactory

/**
 * High-level SSH client API.
 *
 * This is the main entry point for establishing SSH connections.
 *
 * Usage:
 * ```kotlin
 * val client = SshClient("example.com")
 * if (client.connect() && client.authenticatePassword("user", "password")) {
 *     // Connection established and authenticated
 *     client.disconnect()
 * }
 * ```
 */
class SshClient(
    private val host: String,
    private val port: Int = 22,
    private val clientVersion: String = "SSH-2.0-SshProtoClient_1.0"
) {
    companion object {
        private val logger = LoggerFactory.getLogger(SshClient::class.java)
    }

    private var transport: KtorTcpTransport? = null
    private var connection: SshConnection? = null
    private var authenticated = false

    /**
     * Connect to the SSH server and perform key exchange.
     *
     * @return true if connection succeeded
     */
    fun connect(): Boolean {
        try {
            logger.info("Connecting to $host:$port")

            // Create transport and connect
            val ktorTransport = KtorTcpTransport(host, port)
            runBlocking {
                ktorTransport.connect()
            }
            transport = ktorTransport

            // Create SSH connection and perform handshake
            val sshConnection = SshConnection(ktorTransport, clientVersion)
            val success = sshConnection.connect()

            if (success) {
                connection = sshConnection
                logger.info("Successfully connected to $host:$port")
            } else {
                disconnect()
                logger.error("Failed to connect to $host:$port")
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
    fun authenticatePassword(username: String, password: String): Boolean {
        val conn = connection
        if (conn == null) {
            logger.error("Not connected - call connect() first")
            return false
        }

        return try {
            logger.info("Authenticating as $username")
            val success = runBlocking {
                conn.authenticatePassword(username, password)
            }

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
     * @return SessionChannel instance if successful, null otherwise
     */
    fun openSessionChannel(): SessionChannel? {
        val conn = connection
        if (conn == null || !authenticated) {
            logger.error("Not authenticated - call connect() and authenticatePassword() first")
            return null
        }

        return try {
            logger.info("Opening session channel")
            runBlocking {
                conn.openSessionChannel()
            }
        } catch (e: Exception) {
            logger.error("Failed to open session channel", e)
            null
        }
    }

    /**
     * Disconnect from the SSH server.
     */
    fun disconnect() {
        logger.info("Disconnecting from $host:$port")

        connection?.disconnect()
        connection = null

        runBlocking {
            transport?.close()
        }
        transport = null

        authenticated = false
    }
}
