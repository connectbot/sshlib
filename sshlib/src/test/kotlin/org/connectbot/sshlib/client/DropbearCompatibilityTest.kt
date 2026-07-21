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

import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
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
class DropbearCompatibilityTest {

    companion object {
        private val logger = LoggerFactory.getLogger(DropbearCompatibilityTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val OPTIONS_ENV = "OPTIONS"
        private const val USERNAME = "testuser"
        private const val PASSWORD = "testpass"

        private val PUBLIC_KEY_NAMES = arrayOf(
            "ed25519_unencrypted.pub",
            "ecdsa256_unencrypted.pub",
            "ecdsa384_unencrypted.pub",
            "ecdsa521_unencrypted.pub",
            "rsa_unencrypted.pub",
        )

        private val baseImage = ImageFromDockerfile("dropbear-server-test", false)
            .withFileFromClasspath(".", "dropbear-server").also { image ->
                for (key in PUBLIC_KEY_NAMES) {
                    image.withFileFromClasspath(key, "keys/$key")
                }
            }

        @Container
        @JvmStatic
        val server: GenericContainer<*> = createBaseContainer()

        @Suppress("resource")
        private fun createBaseContainer(): GenericContainer<*> = GenericContainer(baseImage)
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(LogMessageWaitStrategy().withRegEx(".*Not backgrounding.*\\s"))

        @JvmStatic
        fun encryptionAlgorithms() = listOf(
            "aes128-ctr",
            "aes256-ctr",
            "chacha20-poly1305@openssh.com",
        )

        @JvmStatic
        fun kexAlgorithms() = listOf(
            "mlkem768x25519-sha256",
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group14-sha256",
        )

        @JvmStatic
        fun macAlgorithms() = listOf(
            "hmac-sha2-256",
        )

        @JvmStatic
        fun pubkeyFiles() = listOf(
            "ed25519_unencrypted",
            "ecdsa256_unencrypted",
            "ecdsa384_unencrypted",
            "ecdsa521_unencrypted",
        )

        @JvmStatic
        fun hostKeyConfigs() = listOf(
            HostKeyConfig("/etc/dropbear/dropbear_ed25519_host_key", "ssh-ed25519"),
            HostKeyConfig("/etc/dropbear/dropbear_ecdsa_host_key", "ecdsa-sha2-nistp256"),
            HostKeyConfig("/etc/dropbear/dropbear_rsa_host_key", "rsa-sha2-256"),
        )

        data class HostKeyConfig(val path: String, val algorithm: String) {
            override fun toString(): String = algorithm
        }
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun connectToServer(configure: (SshClientConfig.Builder.() -> Unit)? = null): BlockingSshClient {
        val host = server.host
        val port = server.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            configure?.invoke(this)
        }
        val client = BlockingSshClient(config)
        client.connect()
        return client
    }

    @Suppress("resource")
    private fun authenticateWithOptions(
        options: String,
        configure: (SshClientConfig.Builder.() -> Unit)? = null,
    ) {
        val customServer = createBaseContainer().withEnv(OPTIONS_ENV, options)
        customServer.start()
        try {
            val host = customServer.host
            val port = customServer.getMappedPort(22)
            val config = SshClientConfig {
                this.host = host
                this.port = port
                this.hostKeyVerifier = acceptAllVerifier
                configure?.invoke(this)
            }
            val client = BlockingSshClient(config)
            try {
                client.connect()
                client.authenticatePassword(USERNAME, PASSWORD)
            } finally {
                client.disconnect()
            }
        } finally {
            customServer.stop()
        }
    }

    private fun authenticateWithPassword(configure: (SshClientConfig.Builder.() -> Unit)? = null) {
        val client = connectToServer(configure)
        try {
            client.authenticatePassword(USERNAME, PASSWORD)
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `can connect with password`() {
        authenticateWithPassword()
    }

    @Test
    fun `wrong password fails`() {
        val client = connectToServer()
        try {
            assertThrows<SshException> { client.authenticatePassword(USERNAME, "wrongpassword") }
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "pubkey: {0}")
    @MethodSource("pubkeyFiles")
    fun `can connect with public key`(keyFilename: String) {
        val keyData = javaClass.getResourceAsStream("/keys/$keyFilename")!!
            .bufferedReader().readText()
        val client = connectToServer()
        try {
            client.authenticatePublicKey(USERNAME, keyData)
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest(name = "hostkey: {0}")
    @MethodSource("hostKeyConfigs")
    fun `can connect to host with key type`(config: HostKeyConfig) {
        authenticateWithOptions("-r ${config.path}") {
            hostKeyAlgorithms = config.algorithm
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
            macAlgorithms = "hmac-sha2-256"
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
