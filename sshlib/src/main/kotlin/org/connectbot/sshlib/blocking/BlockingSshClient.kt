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

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.transport.TransportFactory

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
 * if (client.connect()) {
 *     if (client.authenticatePassword("user", "password")) {
 *         SshSession session = client.openSession();
 *         // ...
 *         session.close();
 *     }
 *     client.disconnect();
 * }
 * ```
 *
 * With custom transport:
 * ```java
 * BlockingSshClient client = new BlockingSshClient(myTransportFactory);
 * ```
 */
class BlockingSshClient private constructor(
    private val client: SshClient
) {
    /**
     * Create a blocking SSH client for TCP connection.
     */
    @JvmOverloads
    constructor(
        host: String,
        port: Int = 22,
        hostKeyVerifier: HostKeyVerifier,
        clientVersion: String = "SSH-2.0-CBSSH_1.0"
    ) : this(SshClientConfig {
        this.host = host
        this.port = port
        this.hostKeyVerifier = hostKeyVerifier
        this.clientVersion = clientVersion
    })

    /**
     * Create a blocking SSH client from configuration.
     */
    constructor(config: SshClientConfig) : this(SshClient(config))

    /**
     * Create a blocking SSH client with custom transport factory.
     */
    constructor(
        transportFactory: TransportFactory,
        clientVersion: String = "SSH-2.0-CBSSH_1.0"
    ) : this(SshClient(transportFactory, clientVersion))

    /**
     * Connect to the SSH server and perform key exchange.
     *
     * @return true if connection succeeded
     */
    fun connect(): Boolean = runBlocking { client.connect() }

    /**
     * Authenticate using password authentication.
     *
     * @param username SSH username
     * @param password SSH password
     * @return true if authentication succeeded
     */
    fun authenticatePassword(username: String, password: String): Boolean =
        runBlocking { client.authenticatePassword(username, password) }

    /**
     * Authenticate using keyboard-interactive authentication (RFC 4256).
     *
     * @param username SSH username
     * @param callback Receives prompts from the server and provides responses
     * @return true if authentication succeeded
     */
    fun authenticateKeyboardInteractive(
        username: String,
        callback: KeyboardInteractiveCallback
    ): Boolean = runBlocking { client.authenticateKeyboardInteractive(username, callback) }

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
     * Disconnect from the SSH server.
     */
    fun disconnect() = runBlocking { client.disconnect() }
}
