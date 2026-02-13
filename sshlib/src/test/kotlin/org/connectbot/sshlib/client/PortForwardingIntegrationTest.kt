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

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.Socks5Authenticator
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

@Testcontainers
@Timeout(30)
class PortForwardingIntegrationTest {

    companion object {
        private val logger = LoggerFactory.getLogger(PortForwardingIntegrationTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val USERNAME = "testuser"
        private const val PASSWORD = "testpass"

        @Container
        @JvmStatic
        val opensshContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("openssh-server-fwd-test", false)
                .withFileFromClasspath(".", "openssh-server")
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Server listening.*", 1)
            )
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun createAuthenticatedClient(): SshClient {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)
        runBlocking {
            assertTrue(client.connect(), "Should connect")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD), "Should authenticate")
        }
        return client
    }

    @Test
    fun `local port forwarding should forward TCP data`() = runBlocking {
        val client = createAuthenticatedClient()

        try {
            // Forward to the SSH server itself on port 22
            val forwarder = client.localPortForward(
                InetSocketAddress("127.0.0.1", 0),
                "127.0.0.1",
                22
            )
            assertNotNull(forwarder, "Should create local port forwarder")
            assertTrue(forwarder!!.isActive, "Forwarder should be active")
            assertTrue(forwarder.boundPort > 0, "Should bind to a real port")

            // Connect through the forwarded port and read SSH banner
            delay(200)
            val socket = Socket("127.0.0.1", forwarder.boundPort)
            socket.soTimeout = 5000
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
            val line = reader.readLine()

            assertTrue(line.startsWith("SSH-"), "Should receive SSH banner, got: $line")

            socket.close()
            forwarder.stop()
            assertFalse(forwarder.isActive, "Forwarder should be stopped")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `local port forward convenience method binds to localhost`() = runBlocking {
        val client = createAuthenticatedClient()

        try {
            val forwarder = client.localPortForward(0, "127.0.0.1", 22)
            assertNotNull(forwarder, "Should create local port forwarder")
            assertTrue(forwarder!!.boundPort > 0)
            assertEquals("127.0.0.1", forwarder.boundHost)
            forwarder.stop()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `remote port forwarding should forward to local service`() = runBlocking {
        val client = createAuthenticatedClient()

        // Start a local TCP server that sends a greeting and reads back
        val localServer = ServerSocket(0)
        val localPort = localServer.localPort
        val receivedData = StringBuilder()

        val serverThread = Thread {
            try {
                val clientSocket = localServer.accept()
                clientSocket.soTimeout = 5000
                val writer = PrintWriter(clientSocket.getOutputStream(), true)
                writer.println("hello from local")
                val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                val line = reader.readLine()
                if (line != null) receivedData.append(line)
                clientSocket.close()
            } catch (_: Exception) {}
        }
        serverThread.isDaemon = true
        serverThread.start()

        try {
            val forwarder = client.remotePortForward(
                "127.0.0.1",
                0,
                "127.0.0.1",
                localPort
            )
            assertNotNull(forwarder, "Should create remote port forwarder")
            assertTrue(forwarder!!.isActive, "Forwarder should be active")
            assertTrue(forwarder.boundPort > 0, "Should have a bound port")

            // Connect through the forwarded port from inside the container using shell+nc
            val session = client.openSession()!!
            session.requestShell()
            delay(200)
            session.write("nc 127.0.0.1 ${forwarder.boundPort} -w 2\n".toByteArray())

            // Give time for the connection and data exchange
            delay(3000)

            forwarder.stop()
            session.close()
        } finally {
            localServer.close()
            client.disconnect()
        }
    }

    @Test
    fun `dynamic port forwarding should handle SOCKS5 connect`() = runBlocking {
        val client = createAuthenticatedClient()

        try {
            val forwarder = client.dynamicPortForward(
                InetSocketAddress("127.0.0.1", 0)
            )
            assertNotNull(forwarder, "Should create dynamic port forwarder")
            assertTrue(forwarder!!.isActive)

            // Connect through SOCKS5 proxy to the SSH server on port 22
            val socksPort = forwarder.boundPort
            val socket = Socket()
            socket.connect(InetSocketAddress("127.0.0.1", socksPort))
            socket.soTimeout = 5000

            val out = socket.getOutputStream()
            val inp = socket.getInputStream()

            // SOCKS5 method selection: version 5, 1 method, NO_AUTH
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()

            // Read method selection response
            val methodReply = ByteArray(2)
            inp.read(methodReply)
            assertEquals(0x05.toByte(), methodReply[0])
            assertEquals(0x00.toByte(), methodReply[1])

            // SOCKS5 CONNECT to 127.0.0.1:22 (the SSH server)
            out.write(
                byteArrayOf(
                    0x05, 0x01, 0x00, // version, CMD_CONNECT, RSV
                    0x01, // ATYP IPv4
                    127, 0, 0, 1, // 127.0.0.1
                    0x00, 0x16 // port 22
                )
            )
            out.flush()

            // Read connect reply (10 bytes: ver, rep, rsv, atyp, 4 addr, 2 port)
            val connectReply = ByteArray(10)
            inp.read(connectReply)
            assertEquals(0x05.toByte(), connectReply[0])
            assertEquals(0x00.toByte(), connectReply[1]) // success

            // Now we should be connected through SSH to the SSH server
            val reader = BufferedReader(InputStreamReader(inp))
            val line = reader.readLine()
            assertTrue(line.startsWith("SSH-"), "Should receive SSH banner, got: $line")

            socket.close()
            forwarder.stop()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `jump host should connect second SSH client through first`() = runBlocking {
        val jumpClient = createAuthenticatedClient()

        try {
            // Use the jump client to create a transport to the same SSH server's port 22
            // inside the container (127.0.0.1:22 from the container's perspective)
            val transportFactory = jumpClient.openDirectTcpipTransport("127.0.0.1", 22)
            assertNotNull(transportFactory, "Should create transport factory")

            val targetConfig = SshClientConfig {
                this.transportFactory = transportFactory!!
                this.hostKeyVerifier = acceptAllVerifier
            }
            val targetClient = SshClient(targetConfig)

            assertTrue(targetClient.connect(), "Should connect through jump host")
            assertTrue(
                targetClient.authenticatePassword(USERNAME, PASSWORD),
                "Should authenticate through jump host"
            )

            // Open a session on the target and run a command
            val session = targetClient.openSession()
            assertNotNull(session, "Should open session through jump host")
            session!!.requestShell()
            delay(200)
            session.write("echo jump-test-ok\n".toByteArray())
            delay(500)

            val output = StringBuilder()
            while (true) {
                val data = session.stdout.tryReceive().getOrNull() ?: break
                output.append(String(data))
            }
            assertTrue(
                output.contains("jump-test-ok"),
                "Should receive command output through jump host, got: $output"
            )

            session.close()
            targetClient.disconnect()
        } finally {
            jumpClient.disconnect()
        }
    }

    @Test
    fun `dynamic port forwarding with authenticator`() = runBlocking {
        val client = createAuthenticatedClient()

        try {
            val authenticator = object : Socks5Authenticator {
                override fun authenticate(username: String, password: String): Boolean = username == "socks_user" && password == "socks_pass"
            }

            val forwarder = client.dynamicPortForward(
                InetSocketAddress("127.0.0.1", 0),
                authenticator
            )
            assertNotNull(forwarder)
            assertTrue(forwarder!!.isActive)

            // Try connecting without auth - should fail since authenticator requires it
            val socket = Socket()
            socket.connect(InetSocketAddress("127.0.0.1", forwarder.boundPort))
            val out = socket.getOutputStream()
            val inp = socket.getInputStream()

            // Offer only NO_AUTH
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()

            val reply = ByteArray(2)
            inp.read(reply)
            assertEquals(0x05.toByte(), reply[0])
            assertEquals(0xFF.toByte(), reply[1]) // NO_ACCEPTABLE_METHODS

            socket.close()
            forwarder.stop()
        } finally {
            client.disconnect()
        }
    }
}
