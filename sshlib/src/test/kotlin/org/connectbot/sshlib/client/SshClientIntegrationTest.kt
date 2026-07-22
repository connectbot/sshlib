/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PingResult
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SessionExit
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.security.MessageDigest
import kotlin.test.assertIs

/**
 * Integration tests for SSH client using testcontainers with real SSH servers.
 */
@Testcontainers
class SshClientIntegrationTest {

    companion object {
        private val logger = LoggerFactory.getLogger(SshClientIntegrationTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val USERNAME = "testuser"
        private const val PASSWORD = "testpass"

        // The OpenSSH version to test against; matches the default ARG in the Dockerfile.
        // To test a different version, change this constant and the cached image will be rebuilt.
        // To enable KEX/PK debug logging, set DEBUG_CFLAGS to e.g.:
        //   "-DDEBUG_KEX -DDEBUG_KEXECDH -DDEBUG_KEXDH -DDEBUG_PK"
        private const val OPENSSH_VERSION = "9.9p2"
        private const val DEBUG_CFLAGS = ""

        private fun opensshImageName(): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("$OPENSSH_VERSION:$DEBUG_CFLAGS".toByteArray())
            val hash = digest.take(4).joinToString("") { "%02x".format(it) }
            return "openssh-server-test-$hash"
        }

        @Container
        @JvmStatic
        val opensshContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile(opensshImageName(), false)
                .withFileFromClasspath(".", "openssh-server")
                .withFileFromClasspath("test_rsa.pub", "keys/rsa_unencrypted.pub")
                .withBuildArg("OPENSSH_VERSION", OPENSSH_VERSION)
                .withBuildArg("DEBUG_CFLAGS", DEBUG_CFLAGS),
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Server listening.*", 1),
            )

        @Container
        @JvmStatic
        val opensshRsaOnlyContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile(opensshImageName() + "-rsa", false)
                .withFileFromClasspath(".", "openssh-server")
                .withFileFromClasspath("test_rsa.pub", "keys/rsa_unencrypted.pub")
                .withBuildArg("OPENSSH_VERSION", OPENSSH_VERSION)
                .withBuildArg("DEBUG_CFLAGS", DEBUG_CFLAGS),
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .withCommand("/usr/sbin/sshd", "-D", "-e", "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=ssh-rsa")
            .waitingFor(
                Wait.forLogMessage(".*Server listening.*", 1),
            )

        @JvmStatic
        fun encryptionAlgorithms() = listOf(
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-ctr",
            "aes256-ctr",
            "aes128-cbc",
            "aes256-cbc",
            "3des-cbc",
        )

        @JvmStatic
        fun kexAlgorithms() = listOf(
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
        )

        @JvmStatic
        fun hostKeyAlgorithms() = listOf(
            "rsa-sha2-256",
            "rsa-sha2-512",
        )

        @JvmStatic
        fun macAlgorithms() = listOf(
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
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
            client.connect()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `ping returns success against real OpenSSH server`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        runBlocking {
            val client = SshClient(
                SshClientConfig {
                    this.host = host
                    this.port = port
                    this.hostKeyVerifier = acceptAllVerifier
                },
            )
            try {
                val connectResult = client.connect()
                assertIs<ConnectResult.Success>(connectResult)

                val authResult = client.authenticatePassword(USERNAME, PASSWORD)
                assertIs<AuthResult.Success>(authResult)

                val pingResult = client.ping()
                assertIs<PingResult.Success>(pingResult)
                assertTrue(pingResult.elapsedNs > 0, "Elapsed time should be positive")
            } finally {
                client.disconnect()
            }
        }
    }

    @Test
    fun `ping returns NotAuthenticated before authentication against real OpenSSH server`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        runBlocking {
            val client = SshClient(
                SshClientConfig {
                    this.host = host
                    this.port = port
                    this.hostKeyVerifier = acceptAllVerifier
                },
            )
            try {
                val connectResult = client.connect()
                assertIs<ConnectResult.Success>(connectResult)

                val pingResult = client.ping()
                assertIs<PingResult.NotAuthenticated>(pingResult)
            } finally {
                client.disconnect()
            }
        }
    }

    @Test
    fun `should authenticate with password`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)
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
            client.connect()
            assertThrows<SshException> { client.authenticatePassword(USERNAME, "wrongpassword") }
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
        client.connect()

        // Authenticate
        client.authenticatePassword(USERNAME, PASSWORD)
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
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)

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
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)

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
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)

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
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)

            val session = client.openSession()
            assertNotNull(session, "Should open session with host key $algorithm")

            val shellRequested = runBlocking { session!!.requestShell() }
            assertTrue(shellRequested, "Should request shell with host key $algorithm")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "mac: {0}")
    @MethodSource("macAlgorithms")
    fun `should connect with mac algorithm`(algorithm: String) {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            // Use a non-AEAD cipher to ensure MAC is used
            this.encryptionAlgorithms = "aes128-ctr"
            this.macAlgorithms = algorithm
        }
        val client = BlockingSshClient(config)

        try {
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)

            val session = client.openSession()
            assertNotNull(session, "Should open session with MAC $algorithm")

            val shellRequested = runBlocking { session!!.requestShell() }
            assertTrue(shellRequested, "Should request shell with MAC $algorithm")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should authenticate with keyboard-interactive`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            client.connect()

            val callback = object : KeyboardInteractiveCallback {
                override suspend fun onInfoRequest(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                    respond: suspend (responses: List<String>) -> Unit,
                ) {
                    respond(prompts.map { PASSWORD })
                }
            }

            client.authenticateKeyboardInteractive(USERNAME, callback)
            assertTrue(client.isAuthenticated, "Client should be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should fail keyboard-interactive with wrong password`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            client.connect()

            val callback = object : KeyboardInteractiveCallback {
                override suspend fun onInfoRequest(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                    respond: suspend (responses: List<String>) -> Unit,
                ) {
                    respond(prompts.map { "wrongpassword" })
                }
            }

            assertThrows<SshException> { client.authenticateKeyboardInteractive(USERNAME, callback) }
            assertFalse(client.isAuthenticated, "Client should not be authenticated")
        } finally {
            client.disconnect()
        }
    }

    // --- AuthHandler integration tests ---

    private fun readTestKey(): String = javaClass.getResourceAsStream("/openssh-server/test_ed25519")!!
        .bufferedReader().readText()

    private fun readRsaTestKey(): String = javaClass.getResourceAsStream("/keys/rsa_unencrypted")!!
        .bufferedReader().readText()

    @Test
    fun `explicit ssh-rsa wishlist enables SHA-1 RSA authentication`() = runBlocking {
        val host = opensshRsaOnlyContainer.host
        val port = opensshRsaOnlyContainer.getMappedPort(22)

        val client = SshClient(
            SshClientConfig {
                this.host = host
                this.port = port
                this.hostKeyVerifier = acceptAllVerifier
                // Force ssh-rsa only by excluding rsa-sha2 variants
                this.hostKeyAlgorithms = "ssh-rsa"
                // Use a single KEX algorithm; SshConnection appends ext-info-c automatically.
                this.kexAlgorithms = "diffie-hellman-group14-sha256"
            },
        )

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")

            val keyData = readRsaTestKey()
            val pubKey = SshSigning.getPublicKey("ssh-rsa", keyData, null)

            val handler = object : AuthHandler {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = listOf(pubKey)
                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray = SshSigning.sign(key.algorithmName, keyData, null, dataToSign)
                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String>? = null
                override suspend fun onPasswordNeeded(): String? = null
            }

            val result = withTimeout(10_000) { client.authenticate(USERNAME, handler) }
            assertTrue(result is AuthResult.Success, "Should authenticate with explicitly enabled ssh-rsa")
            assertTrue(client.isAuthenticated, "Client should be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should connect with rsa-sha2-512 by default when server supports it`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = SshClient(
            SshClientConfig {
                this.host = host
                this.port = port
                this.hostKeyVerifier = acceptAllVerifier
            },
        )

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")

            val keyData = readRsaTestKey()
            // Even if we provide the key as ssh-rsa, it should negotiate rsa-sha2-512
            val pubKey = SshSigning.getPublicKey("ssh-rsa", keyData, null)

            val handler = object : AuthHandler {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = listOf(pubKey)
                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray {
                    // Verify that the negotiated algorithm is rsa-sha2-512
                    assertEquals("rsa-sha2-512", key.algorithmName)
                    return SshSigning.sign(key.algorithmName, keyData, null, dataToSign)
                }
                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String>? = null
                override suspend fun onPasswordNeeded(): String? = null
            }

            val result = withTimeout(10_000) { client.authenticate(USERNAME, handler) }
            assertTrue(result is AuthResult.Success, "Should authenticate with rsa-sha2-512")
            assertTrue(client.isAuthenticated, "Client should be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `auth handler should authenticate with password when preferPasswordAuth is set`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.preferPasswordAuth = true
        }
        val client = BlockingSshClient(config)

        try {
            client.connect()

            var methodsReceived: Set<String>? = null

            val handler = object : AuthHandler {
                override suspend fun onAuthMethodsAvailable(methods: Set<String>) {
                    methodsReceived = methods
                }

                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()

                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null

                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String>? = null

                override suspend fun onPasswordNeeded(): String = PASSWORD
            }

            client.authenticate(USERNAME, handler)
            assertTrue(client.isAuthenticated, "Client should be authenticated")
            assertNotNull(methodsReceived, "Should have received available methods")
            assertTrue(methodsReceived!!.isNotEmpty(), "Available methods should not be empty")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `auth handler should authenticate with keyboard-interactive`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            client.connect()

            val handler = object : AuthHandler {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()

                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null

                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String> = prompts.map { PASSWORD }

                override suspend fun onPasswordNeeded(): String? = null
            }

            client.authenticate(USERNAME, handler)
            assertTrue(client.isAuthenticated, "Client should be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `auth handler should authenticate with public key`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            client.connect()

            val keyData = readTestKey()
            val pubKey = SshSigning.getPublicKey("ssh-ed25519", keyData, null)

            val handler = object : AuthHandler {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = listOf(pubKey)

                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray = SshSigning.sign(key.algorithmName, keyData, null, dataToSign)

                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String>? = null

                override suspend fun onPasswordNeeded(): String? = null
            }

            client.authenticate(USERNAME, handler)
            assertTrue(client.isAuthenticated, "Client should be authenticated")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `auth handler should fall through pubkey to keyboard-interactive`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = BlockingSshClient(host, port, acceptAllVerifier)

        try {
            client.connect()

            val callSequence = mutableListOf<String>()

            val handler = object : AuthHandler {
                override suspend fun onAuthMethodsAvailable(methods: Set<String>) {
                    callSequence.add("methods")
                }

                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> {
                    callSequence.add("pubkeys")
                    // Return a fake key that won't be accepted
                    return listOf(AuthPublicKey("ssh-ed25519", ByteArray(51)))
                }

                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? {
                    callSequence.add("sign")
                    return null
                }

                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String> {
                    callSequence.add("kbd")
                    return prompts.map { PASSWORD }
                }

                override suspend fun onPasswordNeeded(): String? {
                    callSequence.add("password")
                    return null
                }
            }

            client.authenticate(USERNAME, handler)
            assertTrue(client.isAuthenticated, "Client should be authenticated")
            assertTrue("methods" in callSequence, "onAuthMethodsAvailable should have been called")
            assertTrue("pubkeys" in callSequence, "onPublicKeysNeeded should have been called")
            assertTrue("kbd" in callSequence, "onKeyboardInteractivePrompt should have been called")
            assertTrue("password" !in callSequence, "onPasswordNeeded should not have been called")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `auth handler should report available methods`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.preferPasswordAuth = true
        }
        val client = BlockingSshClient(config)

        try {
            client.connect()

            var receivedMethods: Set<String>? = null

            val handler = object : AuthHandler {
                override suspend fun onAuthMethodsAvailable(methods: Set<String>) {
                    receivedMethods = methods
                }

                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()

                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null

                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String>? = null

                override suspend fun onPasswordNeeded(): String = PASSWORD
            }

            client.authenticate(USERNAME, handler)
            val methods = receivedMethods ?: fail("Should have received available methods")
            assertTrue("publickey" in methods, "Should include publickey method")
            assertTrue("password" in methods, "Should include password method")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should execute command with exec channel`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            val execResult = session!!.requestExec("echo hello-exec")
            assertTrue(execResult, "Should successfully request exec")

            val output = withTimeout(5_000) {
                val buf = StringBuilder()
                while (true) {
                    val data = session.read() ?: break
                    buf.append(String(data))
                }
                buf.toString()
            }

            assertTrue(output.contains("hello-exec"), "Should receive command output: $output")

            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should execute command with exec channel and read stderr`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            val execResult = session!!.requestExec("echo error-output >&2")
            assertTrue(execResult, "Should successfully request exec")

            val stderr = withTimeout(5_000) {
                val buf = StringBuilder()
                while (true) {
                    val data = session.stderr.receiveCatching().getOrNull() ?: break
                    buf.append(String(data))
                }
                buf.toString()
            }

            assertTrue(stderr.contains("error-output"), "Should receive stderr output: $stderr")

            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should surface exec exit status`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)
        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            assertTrue(session!!.requestExec("sh -c 'exit 42'"), "Should successfully request exec")

            // Drain stdout to EOF first — the exit report follows the data.
            withTimeout(5_000) {
                while (session.read() != null) {
                    // discard
                }
            }
            val exit = withTimeout(5_000) { session.exitInfo.await() }
            assertEquals(SessionExit.Status(42L), exit)

            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should surface exec exit signal`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)
        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            assertTrue(session!!.requestExec("sh -c 'kill -KILL \$\$'"), "Should successfully request exec")

            withTimeout(5_000) {
                while (session.read() != null) {
                    // discard
                }
            }
            val exit = withTimeout(5_000) { session.exitInfo.await() }
            assertTrue(
                exit is SessionExit.Signal && exit.signalName == "KILL",
                "Expected KILL exit-signal, got: $exit",
            )

            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `rekey occurs when byte limit is exceeded`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            // Keep this above handshake/auth traffic so re-key is triggered by session data.
            this.rekeyBytesLimit = 8_192L
            this.rekeyIntervalMs = Long.MAX_VALUE
        }
        val client = SshClient(config)

        try {
            val result = withTimeout(30_000) { client.connect() }
            assertTrue(result is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            val execResult = session!!.requestExec("dd if=/dev/urandom bs=1024 count=64 2>/dev/null | base64")
            assertTrue(execResult, "Should successfully request exec")

            val output = withTimeout(10_000) {
                val buf = StringBuilder()
                while (true) {
                    val data = session.read() ?: break
                    buf.append(String(data))
                }
                buf.toString()
            }

            assertTrue(output.length > 1_024, "Should receive enough output to cross rekey threshold")
            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should open sftp subsystem and exchange version`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            val subsystemResult = session!!.requestSubsystem("sftp")
            assertTrue(subsystemResult, "Should successfully request sftp subsystem")

            // Send SSH_FXP_INIT (type=1, length=5, version=3)
            val initPacket = byteArrayOf(
                0, 0, 0, 5, // length: 5 bytes (type + version)
                1, // SSH_FXP_INIT
                0, 0, 0, 3, // version 3
            )
            session.write(initPacket)

            // Read SSH_FXP_VERSION response
            val response = withTimeout(5_000) {
                val buf = mutableListOf<Byte>()
                while (buf.size < 9) {
                    val data = session.read() ?: break
                    buf.addAll(data.toList())
                }
                buf.toByteArray()
            }

            assertTrue(response.size >= 9, "Should receive at least 9 bytes (length + type + version)")
            // type byte is at offset 4
            val type = response[4].toInt() and 0xFF
            assertTrue(type == 2, "Response type should be SSH_FXP_VERSION (2), got $type")
            // version is at offset 5-8 (big-endian uint32)
            val version = ((response[5].toInt() and 0xFF) shl 24) or
                ((response[6].toInt() and 0xFF) shl 16) or
                ((response[7].toInt() and 0xFF) shl 8) or
                (response[8].toInt() and 0xFF)
            assertTrue(version >= 3, "SFTP version should be >= 3, got $version")

            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should reject unknown subsystem`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)

            val result = session!!.requestSubsystem("nonexistent-subsystem")
            assertFalse(result, "Should reject unknown subsystem")

            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should connect with compression enabled`() {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.enableCompression = true
        }
        val client = BlockingSshClient(config)

        try {
            client.connect()
            client.authenticatePassword(USERNAME, PASSWORD)

            val session = client.openSession()
            assertNotNull(session, "Should open session with compression enabled")

            val shellRequested = runBlocking { session!!.requestShell() }
            assertTrue(shellRequested, "Should request shell with compression enabled")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should exchange data with compression enabled`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.enableCompression = true
        }
        val client = SshClient(config)

        try {
            withTimeout(30_000) {
                assertTrue(client.connect() is ConnectResult.Success, "Should connect with compression")
                assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

                val session = client.openSession()
                assertNotNull(session)
                session!!.requestPty()
                session.requestShell()

                session.write("echo hello-compression\n".toByteArray())

                val output = withTimeout(10_000) {
                    val buf = StringBuilder()
                    while (!buf.contains("hello-compression")) {
                        val data = session.read() ?: break
                        buf.append(String(data))
                    }
                    buf.toString()
                }

                assertTrue(output.contains("hello-compression"), "Should receive echoed data through compressed connection")

                session.close()
            }
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `disconnectedFlow emits when server closes channel`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val disconnectDeferred = async {
                withTimeout(10_000) {
                    client.disconnectedFlow.first()
                }
            }

            yield()

            val session = client.openSession()
            assertNotNull(session)
            session!!.requestShell()
            session.write("exit\n".toByteArray())

            // Client detects all channels closed and disconnects cleanly
            val cause = disconnectDeferred.await()
            assertNull(cause)
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `disconnectedFlow emits with error when server kills connection`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val disconnectDeferred = async {
                withTimeout(10_000) {
                    client.disconnectedFlow.first()
                }
            }

            kotlinx.coroutines.yield()

            val session = client.openSession()
            assertNotNull(session)
            session!!.requestShell()

            // Kill our sshd child process from the server side.
            // This drops the TCP connection without SSH_MSG_DISCONNECT.
            session.write("kill -9 \$PPID\n".toByteArray())

            val cause = disconnectDeferred.await()
            assertNotNull(cause, "Should emit non-null Throwable on forced disconnect")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `session channel closes after server-side TCP drop`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)
            session!!.requestShell()

            val disconnectDeferred = async {
                withTimeout(10_000) {
                    client.disconnectedFlow.first()
                }
            }

            kotlinx.coroutines.yield()

            // Force kill the server-side connection
            session.write("kill -9 \$PPID\n".toByteArray())

            // Wait for disconnectedFlow to fire (so we know the packet loop ended)
            disconnectDeferred.await()

            assertFalse(session.isOpen, "Session should be closed after server drops connection")
            assertNull(session.read(), "Read should return null on closed session")
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `disconnectedFlow does not emit on client-initiated disconnect`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
        assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

        val session = client.openSession()
        assertNotNull(session)
        session!!.requestShell()

        var emitted = false
        val collectJob = async {
            client.disconnectedFlow.first()
            emitted = true
        }

        kotlinx.coroutines.yield()

        // Client-initiated disconnect
        client.disconnect()

        // Give time for any erroneous emission to propagate
        delay(500)

        assertFalse(emitted, "disconnectedFlow should not emit on client-initiated disconnect")
        collectJob.cancel()
    }

    @Test
    fun `read returns null after server kills connection`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")
            assertTrue(client.authenticatePassword(USERNAME, PASSWORD) is AuthResult.Success, "Should authenticate")

            val session = client.openSession()
            assertNotNull(session)
            session!!.requestShell()

            // Start a blocking read before killing the connection
            val readDeferred = async {
                // Drain any initial shell output, then wait for more
                while (true) {
                    val data = session.read() ?: break
                }
            }

            // Give time for the read to be waiting
            delay(200)

            // Force kill the server-side connection
            session.write("kill -9 \$PPID\n".toByteArray())

            // The read should complete with null (channel closed)
            withTimeout(10_000) {
                readDeferred.await()
            }
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should open shell after failed then successful auth handler authenticate`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = SshClient(
            SshClientConfig {
                this.host = host
                this.port = port
                this.hostKeyVerifier = acceptAllVerifier
                // Restricted config to remove possible culprits
                this.encryptionAlgorithms = "aes128-ctr"
                this.macAlgorithms = "hmac-sha2-256"
                this.kexAlgorithms = "ecdh-sha2-nistp256"
                this.enableCompression = false
            },
        )

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")

            val failingHandler = object : AuthHandler {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()
                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null
                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String> = prompts.map { "wrongpassword" }
                override suspend fun onPasswordNeeded(): String? = null
            }

            val firstResult = withTimeout(10_000) { client.authenticate(USERNAME, failingHandler) }
            assertTrue(firstResult is AuthResult.Failure, "First authenticate should fail with wrong password")
            assertFalse(client.isAuthenticated, "Client should not be authenticated after first failure")

            val succeedingHandler = object : AuthHandler {
                override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()
                override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null
                override suspend fun onKeyboardInteractivePrompt(
                    name: String,
                    instruction: String,
                    prompts: List<KeyboardInteractiveCallback.Prompt>,
                ): List<String> = prompts.map { PASSWORD }
                override suspend fun onPasswordNeeded(): String = PASSWORD
            }

            val secondResult = withTimeout(10_000) { client.authenticate(USERNAME, succeedingHandler) }
            assertTrue(secondResult is AuthResult.Success, "Second authenticate should succeed with correct password")
            assertTrue(client.isAuthenticated, "Client should be authenticated after second attempt")

            val session = withTimeout(10_000) { client.openSession() }
            assertNotNull(session, "Should open session after retry authentication")

            val ptyGranted = withTimeout(10_000) { session!!.requestPty() }
            assertTrue(ptyGranted, "Should grant PTY after retry authentication")

            val shellGranted = withTimeout(10_000) { session!!.requestShell() }
            assertTrue(shellGranted, "Should spawn shell after retry authentication")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `should open shell after failed then successful authenticatePassword`() = runBlocking {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val client = SshClient(
            SshClientConfig {
                this.host = host
                this.port = port
                this.hostKeyVerifier = acceptAllVerifier
                // Restricted config to remove possible culprits
                this.encryptionAlgorithms = "aes128-ctr"
                this.macAlgorithms = "hmac-sha2-256"
                this.kexAlgorithms = "ecdh-sha2-nistp256"
                this.enableCompression = false
            },
        )

        try {
            assertTrue(client.connect() is ConnectResult.Success, "Should connect to SSH server")

            val firstResult = withTimeout(10_000) { client.authenticatePassword(USERNAME, "wrongpassword") }
            assertTrue(firstResult is AuthResult.Failure, "First authenticate should fail with wrong password")
            assertFalse(client.isAuthenticated, "Client should not be authenticated after first failure")

            val secondResult = withTimeout(10_000) { client.authenticatePassword(USERNAME, PASSWORD) }
            assertTrue(secondResult is AuthResult.Success, "Second authenticate should succeed with correct password")
            assertTrue(client.isAuthenticated, "Client should be authenticated after second attempt")

            val session = withTimeout(10_000) { client.openSession() }
            assertNotNull(session, "Should open session after retry authentication")

            val ptyGranted = withTimeout(10_000) { session!!.requestPty() }
            assertTrue(ptyGranted, "Should grant PTY after retry authentication")

            val shellGranted = withTimeout(10_000) { session!!.requestShell() }
            assertTrue(shellGranted, "Should spawn shell after retry authentication")

            session!!.close()
        } finally {
            client.disconnect()
        }
    }
}
