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

package org.connectbot.sshlib.example

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportFactory

/**
 * Example usage of the SSH client.
 *
 * This example demonstrates the basic usage pattern for connecting
 * to an SSH server and authenticating with password.
 */
fun main() = runBlocking {
    // Using the async API with coroutines
    val client = SshClient(
        host = "example.com",
        port = 22
    )

    try {
        // Connect and perform key exchange
        if (!client.connect()) {
            println("Failed to connect to SSH server")
            return@runBlocking
        }

        println("Connected to SSH server")

        // Authenticate with password
        if (!client.authenticatePassword("username", "password")) {
            println("Authentication failed")
            return@runBlocking
        }

        println("Successfully authenticated!")

        // Open a session and request a shell
        val session = client.openSession()
        if (session != null) {
            println("Session opened: local=${session.localChannelNumber}, remote=${session.remoteChannelNumber}")

            // Request a PTY
            if (session.requestPty()) {
                println("PTY allocated")
            }

            // Request a shell
            if (session.requestShell()) {
                println("Shell started")
            }

            session.close()
        }

    } finally {
        client.disconnect()
        println("Disconnected from SSH server")
    }
}

/**
 * Example using the blocking API for Java compatibility.
 */
fun blockingExample() {
    val client = BlockingSshClient("example.com")

    try {
        when {
            !client.connect() -> {
                println("ERROR: Failed to connect to SSH server")
                return
            }
            !client.authenticatePassword("user", "pass") -> {
                println("ERROR: Authentication failed")
                return
            }
            !client.isAuthenticated -> {
                println("ERROR: Client not authenticated")
                return
            }
            else -> {
                println("SUCCESS: Connected and authenticated")

                // Open a session using the blocking API
                val session = client.openSession()
                if (session != null) {
                    // Note: session methods are suspend, so wrap in runBlocking
                    runBlocking {
                        session.requestPty()
                        session.requestShell()
                    }
                    session.close()
                }
            }
        }
    } catch (e: Exception) {
        println("ERROR: Unexpected exception: ${e.message}")
        e.printStackTrace()
    } finally {
        client.disconnect()
    }
}

/**
 * Example using the configuration DSL.
 */
fun configExample() = runBlocking {
    val config = SshClientConfig {
        host = "example.com"
        port = 22
        clientVersion = "SSH-2.0-MyCustomClient_1.0"
    }

    val client = SshClient(config)

    try {
        if (client.connect()) {
            println("Connected with custom config")
        }
    } finally {
        client.disconnect()
    }
}

/**
 * Example using a custom transport factory.
 *
 * This demonstrates how to use the library with any byte stream transport,
 * not just TCP sockets.
 */
fun customTransportExample() = runBlocking {
    // Example: Create a custom transport factory
    val customFactory = TransportFactory {
        // Return your custom Transport implementation
        // This could be:
        // - Unix domain sockets
        // - Serial port
        // - WebSocket
        // - In-memory transport for testing
        // - Wrapper around existing InputStream/OutputStream
        object : Transport {
            override suspend fun read(count: Int): ByteArray {
                // Read from your custom source
                TODO("Implement read from your transport")
            }

            override suspend fun write(data: ByteArray) {
                // Write to your custom destination
                TODO("Implement write to your transport")
            }

            override suspend fun close() {
                // Clean up resources
            }

            override val isConnected: Boolean = true
        }
    }

    // Use the custom transport with SshClient
    val client = SshClient(customFactory)

    try {
        if (client.connect()) {
            println("Connected via custom transport")
        }
    } finally {
        client.disconnect()
    }
}

/**
 * Example using configuration with custom transport.
 */
fun configWithCustomTransportExample() = runBlocking {
    val config = SshClientConfig {
        // Set a custom transport factory instead of host/port
        transportFactory = TransportFactory {
            // Your custom transport
            TODO("Return your Transport implementation")
        }
        clientVersion = "SSH-2.0-CustomTransport_1.0"
    }

    val client = SshClient(config)

    try {
        if (client.connect()) {
            println("Connected via custom transport from config")
        }
    } finally {
        client.disconnect()
    }
}
