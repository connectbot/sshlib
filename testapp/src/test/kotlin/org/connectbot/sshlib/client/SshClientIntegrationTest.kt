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
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
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
//@Disabled("Integration tests fail - needs debugging with real SSH servers")
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
    }

    @Test
    fun `should connect to OpenSSH server`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port)

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

        val client = BlockingSshClient(host, port)

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

        val client = BlockingSshClient(host, port)

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

        val client = BlockingSshClient(host, port)

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

        val client = BlockingSshClient(host, port)

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
}
