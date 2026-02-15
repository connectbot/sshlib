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

import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

@Testcontainers
class AsyncSshCompatibilityTest {

    companion object {
        private val logger = LoggerFactory.getLogger(AsyncSshCompatibilityTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val USERNAME = "testuser"
        private const val PASSWORD = "testpass"

        private val PUBLIC_KEY_NAMES = arrayOf(
            "ed25519_unencrypted.pub",
            "ecdsa256_unencrypted.pub",
            "ecdsa384_unencrypted.pub",
            "ecdsa521_unencrypted.pub",
            "rsa_unencrypted.pub"
        )

        private val baseImage = ImageFromDockerfile("asyncssh-server-test", false)
            .withFileFromClasspath(".", "asyncssh-server").also { image ->
                for (key in PUBLIC_KEY_NAMES) {
                    image.withFileFromClasspath(key, "keys/$key")
                }
            }

        @Container
        @JvmStatic
        val server: GenericContainer<*> = GenericContainer(baseImage)
            .withExposedPorts(8022)
            .withLogConsumer(logConsumer)
            .waitingFor(LogMessageWaitStrategy().withRegEx(".*LISTENER READY.*\\s"))

        @JvmStatic
        fun encryptionAlgorithms() = listOf(
            "chacha20-poly1305@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-ctr",
            "aes256-ctr",
            "aes128-cbc",
            "aes256-cbc",
            "3des-cbc"
        )

        @JvmStatic
        fun kexAlgorithms() = listOf(
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1"
        )

        @JvmStatic
        fun macAlgorithms() = listOf(
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1-etm@openssh.com",
            "hmac-sha1"
        )

        @JvmStatic
        fun pubkeyFiles() = listOf(
            "ed25519_unencrypted",
            "ecdsa256_unencrypted",
            "ecdsa384_unencrypted",
            "ecdsa521_unencrypted",
            "rsa_unencrypted"
        )
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun connectToServer(configure: (SshClientConfig.Builder.() -> Unit)? = null): BlockingSshClient {
        val host = server.host
        val port = server.getMappedPort(8022)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            configure?.invoke(this)
        }
        val client = BlockingSshClient(config)
        assertTrue(client.connect(), "Should connect to AsyncSSH server")
        return client
    }

    private fun authenticateWithPassword(configure: (SshClientConfig.Builder.() -> Unit)? = null) {
        val client = connectToServer(configure)
        try {
            assertTrue(
                client.authenticatePassword(USERNAME, PASSWORD),
                "Should authenticate with password"
            )
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `can connect with password`() {
        authenticateWithPassword()
    }

    @ParameterizedTest(name = "pubkey: {0}")
    @MethodSource("pubkeyFiles")
    fun `can connect with public key`(keyFilename: String) {
        val keyData = javaClass.getResourceAsStream("/keys/$keyFilename")!!
            .bufferedReader().readText()
        val client = connectToServer()
        try {
            assertTrue(
                client.authenticatePublicKey(USERNAME, keyData),
                "Should authenticate with $keyFilename"
            )
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "kex: {0}")
    @MethodSource("kexAlgorithms")
    fun `can connect with kex algorithm`(algorithm: String) {
        authenticateWithPassword {
            kexAlgorithms = "$algorithm,kex-strict-c-v00@openssh.com"
        }
    }

    @ParameterizedTest(name = "encryption: {0}")
    @MethodSource("encryptionAlgorithms")
    fun `can connect with encryption algorithm`(algorithm: String) {
        authenticateWithPassword {
            encryptionAlgorithms = algorithm
        }
    }

    @ParameterizedTest(name = "mac: {0}")
    @MethodSource("macAlgorithms")
    fun `can connect with mac algorithm`(algorithm: String) {
        authenticateWithPassword {
            encryptionAlgorithms = "aes128-ctr"
            macAlgorithms = algorithm
        }
    }
}
