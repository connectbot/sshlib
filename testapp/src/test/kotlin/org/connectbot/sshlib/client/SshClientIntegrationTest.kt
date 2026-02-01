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
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

/**
 * Integration tests for SSH client using testcontainers with real SSH servers.
 *
 * NOTE: These tests currently fail due to issues in the SSH protocol implementation.
 * The client can be built and used programmatically, but needs debugging to work
 * with real SSH servers.
 *
 * Known issues to investigate:
 * - Key exchange negotiation may not match server expectations
 * - Packet framing/encryption activation timing
 * - Server key verification not implemented
 *
 * To enable these tests for debugging:
 * 1. Remove the @Disabled annotation
 * 2. Ensure Docker is installed and running
 * 3. Add detailed logging to SshConnection and PacketIO
 */
@Testcontainers
class SshClientIntegrationTest {

    companion object {
        private val logger = LoggerFactory.getLogger(SshClientIntegrationTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val USERNAME = "testuser"
        private const val PASSWORD = "testpass"

        /**
         * Create OpenSSH server container.
         */
        @Container
        @JvmStatic
        val opensshContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("openssh-server-test", false)
                .withFileFromClasspath(".", "openssh-server")
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Server listening.*", 1)
            )

        @JvmStatic
        fun encryptionAlgorithms() = listOf(
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-ctr",
            "aes256-ctr",
        )

        @JvmStatic
        fun kexAlgorithms() = listOf(
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1",
        )

        @JvmStatic
        fun hostKeyAlgorithms() = listOf(
            "rsa-sha2-256",
            "rsa-sha2-512",
        )
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    @Test
    fun `should connect to OpenSSH server`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            val connected = client.connect()
            assertTrue(connected, "Should successfully connect to SSH server")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should authenticate with password`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            assertTrue(client.connect(), "Should connect to SSH server")

            val authenticated = client.authenticatePassword(USERNAME, PASSWORD)
            assertTrue(authenticated, "Should authenticate with correct password")
            assertTrue(client.isAuthenticated, "Client should be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should fail authentication with wrong password`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            assertTrue(client.connect(), "Should connect to SSH server")

            val authenticated = client.authenticatePassword(USERNAME, "wrongpassword")
            assertFalse(authenticated, "Should fail authentication with wrong password")
            assertFalse(client.isAuthenticated, "Client should not be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should handle connection lifecycle`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        // Initial state
        assertFalse(client.isAuthenticated, "Should not be authenticated initially")

        // Connect
        assertTrue(client.connect(), "Should connect successfully")

        // Authenticate
        assertTrue(
            client.authenticatePassword(USERNAME, PASSWORD),
            "Should authenticate successfully"
        )
        assertTrue(client.isAuthenticated, "Should be authenticated after successful auth")

        // Disconnect
        client.disconnect()
        assertFalse(client.isAuthenticated, "Should not be authenticated after disconnect")
    }

    @Test
    fun `should open session channel and request shell`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            assertTrue(client.connect(), "Should connect to SSH server")
            assertTrue(
                client.authenticatePassword(USERNAME, PASSWORD),
                "Should authenticate successfully"
            )

            val session = client.openSession()
            assertNotNull(session, "Should successfully open session channel")
            assertTrue(session!!.isOpen, "Channel should be open")

            val shellRequested = runBlocking { session.requestShell() }
            assertTrue(shellRequested, "Should successfully request shell")

            session.close()
            assertFalse(session.isOpen, "Channel should be closed")
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "encryption: {0}")
    @MethodSource("encryptionAlgorithms")
    fun `should connect with encryption algorithm`(algorithm: String) {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.encryptionAlgorithms = algorithm
        }
        val client = BlockingSshClient(config)

        try {
            assertTrue(client.connect(), "Should connect with encryption $algorithm")
            assertTrue(
                client.authenticatePassword(USERNAME, PASSWORD),
                "Should authenticate with encryption $algorithm"
            )

            val session = client.openSession()
            assertNotNull(session, "Should open session with encryption $algorithm")

            val shellRequested = runBlocking { session!!.requestShell() }
            assertTrue(shellRequested, "Should request shell with encryption $algorithm")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "kex: {0}")
    @MethodSource("kexAlgorithms")
    fun `should connect with kex algorithm`(algorithm: String) {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.kexAlgorithms = "$algorithm,kex-strict-c-v00@openssh.com"
        }
        val client = BlockingSshClient(config)

        try {
            assertTrue(client.connect(), "Should connect with kex $algorithm")
            assertTrue(
                client.authenticatePassword(USERNAME, PASSWORD),
                "Should authenticate with kex $algorithm"
            )

            val session = client.openSession()
            assertNotNull(session, "Should open session with kex $algorithm")

            val shellRequested = runBlocking { session!!.requestShell() }
            assertTrue(shellRequested, "Should request shell with kex $algorithm")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "hostkey: {0}")
    @MethodSource("hostKeyAlgorithms")
    fun `should connect with host key algorithm`(algorithm: String) {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.hostKeyAlgorithms = algorithm
        }
        val client = BlockingSshClient(config)

        try {
            assertTrue(client.connect(), "Should connect with host key $algorithm")
            assertTrue(
                client.authenticatePassword(USERNAME, PASSWORD),
                "Should authenticate with host key $algorithm"
            )

            val session = client.openSession()
            assertNotNull(session, "Should open session with host key $algorithm")

            val shellRequested = runBlocking { session!!.requestShell() }
            assertTrue(shellRequested, "Should request shell with host key $algorithm")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }
}
