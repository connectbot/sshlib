/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.sk.SkAlgorithm
import org.connectbot.sshlib.sk.SkAuthHelpers
import org.connectbot.sshlib.sk.SkSignatureBlob
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.NamedParameterSpec
import java.util.Base64
import java.security.PublicKey as JcaPublicKey

/**
 * End-to-end integration tests that authenticate to a real OpenSSH server
 * using SK (FIDO2 / Security Key) algorithms.
 *
 * No real FIDO2 hardware is used. The test acts as a software SK authenticator:
 * it generates an Ed25519 or ECDSA-P256 keypair at startup, computes the
 * `authenticatorData || SHA-256(challenge)` payload per OpenSSH `PROTOCOL.u2f`
 * §3.2, signs it with the keypair, and packages the result via
 * [SkSignatureBlob.pack]. If OpenSSH accepts the auth, the wire format is
 * correct.
 *
 * Both `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`
 * are exercised.
 */
@Testcontainers
class SkAuthIntegrationTest {

    companion object {
        private val logger = LoggerFactory.getLogger(SkAuthIntegrationTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val USERNAME = "testuser"
        private const val OPENSSH_VERSION = "9.9p2"
        private const val APPLICATION = "ssh:test"

        // Reuse the shared openssh-server Dockerfile (same as other integration tests).
        @Container
        @JvmStatic
        val opensshContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("openssh-sftp-test", false)
                .withFileFromClasspath(".", "openssh-server")
                .withFileFromClasspath("test_rsa.pub", "keys/rsa_unencrypted.pub")
                .withBuildArg("OPENSSH_VERSION", OPENSSH_VERSION),
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(Wait.forLogMessage(".*Server listening.*", 1))

        private val ed25519KeyPair: KeyPair by lazy { generateEd25519KeyPair() }
        private val ecdsaP256KeyPair: KeyPair by lazy { generateEcdsaP256KeyPair() }
        private val containerSetUp = java.util.concurrent.atomic.AtomicBoolean(false)

        /**
         * Append SK authorized_keys entries for our generated test keypairs and
         * widen `PubkeyAcceptedAlgorithms` to include `sk-*`. Idempotent — the
         * first invocation does the work; subsequent invocations are cheap.
         */
        private fun setUpContainerForSk() {
            if (!containerSetUp.compareAndSet(false, true)) return

            // Allow sk-* publickey algorithms server-side (default in 9.9 includes them,
            // but the Dockerfile's existing config tweaks may have narrowed it).
            val sshdExtraConfig = "PubkeyAcceptedAlgorithms +sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"
            opensshContainer.execInContainer("sh", "-c", "echo '$sshdExtraConfig' >> /etc/ssh/sshd_config && killall -HUP sshd")

            val edAuthLine = authorizedKeysLine(SkAlgorithm.ED25519, ed25519PublicKeyRaw(ed25519KeyPair.public), "ed25519-sk-test")
            val ecAuthLine = authorizedKeysLine(SkAlgorithm.ECDSA_P256, ecdsaP256PublicKeyPoint(ecdsaP256KeyPair.public), "ecdsa-p256-sk-test")
            val combined = edAuthLine + "\n" + ecAuthLine + "\n"
            val cmd = "echo '$combined' >> /home/$USERNAME/.ssh/authorized_keys && chown $USERNAME:$USERNAME /home/$USERNAME/.ssh/authorized_keys"
            val result = opensshContainer.execInContainer("sh", "-c", cmd)
            check(result.exitCode == 0) {
                "Failed to install SK authorized_keys: stdout=${result.stdout} stderr=${result.stderr}"
            }
        }

        private fun authorizedKeysLine(algorithm: SkAlgorithm, rawKey: ByteArray, comment: String): String {
            val blob = org.connectbot.sshlib.sk.SkPublicKeyEncoder.encode(algorithm, rawKey, APPLICATION)
            val base64 = Base64.getEncoder().encodeToString(blob)
            return "${algorithm.sshName} $base64 $comment"
        }

        private fun generateEd25519KeyPair(): KeyPair {
            val gen = java.security.KeyPairGenerator.getInstance("Ed25519")
            gen.initialize(NamedParameterSpec.ED25519, SecureRandom())
            return gen.generateKeyPair()
        }

        private fun generateEcdsaP256KeyPair(): KeyPair {
            val gen = java.security.KeyPairGenerator.getInstance("EC")
            gen.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            return gen.generateKeyPair()
        }

        /** Extract the raw 32-byte Ed25519 public key from a JCA EdECPublicKey. */
        private fun ed25519PublicKeyRaw(jcaPub: JcaPublicKey): ByteArray {
            val edPub = jcaPub as EdECPublicKey
            val point = edPub.point
            // JCA returns the y-coordinate as BigInteger; the encoding is little-endian 32 bytes
            // with the sign bit (xOdd) in the high bit of the last byte.
            val yBytes = point.y.toByteArray()
            // Reverse to little-endian and pad/trim to 32 bytes
            val little = ByteArray(32)
            val reversed = yBytes.reversedArray()
            System.arraycopy(reversed, 0, little, 0, minOf(reversed.size, 32))
            if (point.isXOdd) {
                little[31] = (little[31].toInt() or 0x80).toByte()
            }
            return little
        }

        /** Extract the uncompressed SEC1 EC point (`0x04 || X(32) || Y(32)`) from a JCA ECPublicKey. */
        private fun ecdsaP256PublicKeyPoint(jcaPub: JcaPublicKey): ByteArray {
            val ecPub = jcaPub as ECPublicKey
            val x = padTo32(ecPub.w.affineX.toByteArray())
            val y = padTo32(ecPub.w.affineY.toByteArray())
            return byteArrayOf(0x04) + x + y
        }

        private fun padTo32(bytes: ByteArray): ByteArray {
            if (bytes.size == 32) return bytes
            if (bytes.size > 32) return bytes.copyOfRange(bytes.size - 32, bytes.size)
            val out = ByteArray(32)
            System.arraycopy(bytes, 0, out, 32 - bytes.size, bytes.size)
            return out
        }
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    // ---------------------- Ed25519 SK ----------------------

    @Test
    fun `authenticates with sk-ssh-ed25519@openssh dot com via AuthHandler`() = runBlocking {
        setUpContainerForSk()

        val handler = SoftwareSkAuthHandler(
            algorithm = SkAlgorithm.ED25519,
            rawPublicKey = ed25519PublicKeyRaw(ed25519KeyPair.public),
            privateKey = ed25519KeyPair.private,
        )
        val result = connectAndAuthenticate(handler)
        assertTrue(result is AuthResult.Success, "SK Ed25519 auth should succeed, got: $result")
    }

    // ---------------------- ECDSA-P256 SK ----------------------

    @Test
    fun `authenticates with sk-ecdsa-sha2-nistp256@openssh dot com via AuthHandler`() = runBlocking {
        setUpContainerForSk()

        val handler = SoftwareSkAuthHandler(
            algorithm = SkAlgorithm.ECDSA_P256,
            rawPublicKey = ecdsaP256PublicKeyPoint(ecdsaP256KeyPair.public),
            privateKey = ecdsaP256KeyPair.private,
        )
        val result = connectAndAuthenticate(handler)
        assertTrue(result is AuthResult.Success, "SK ECDSA-P256 auth should succeed, got: $result")
    }

    private suspend fun connectAndAuthenticate(handler: AuthHandler): AuthResult {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        val connectResult = client.connect()
        assertTrue(connectResult is ConnectResult.Success, "Should connect, got: $connectResult")

        return try {
            client.authenticate(USERNAME, handler)
        } finally {
            client.disconnect()
        }
    }

    /**
     * Simulates a FIDO2 SK authenticator using local JCA keys. Per OpenSSH
     * `PROTOCOL.u2f` §3.2, the device-signed payload is:
     *
     * ```
     * SHA-256(application) || flags || counter (big-endian uint32) || SHA-256(challenge)
     * ```
     *
     * where `challenge` is the SSH `dataToSign` blob.
     */
    private class SoftwareSkAuthHandler(
        private val algorithm: SkAlgorithm,
        private val rawPublicKey: ByteArray,
        private val privateKey: PrivateKey,
    ) : AuthHandler {

        override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = listOf(SkAuthHelpers.buildAuthPublicKey(algorithm, rawPublicKey, APPLICATION))

        override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? {
            val flags: Byte = SkSignatureBlob.FLAG_USER_PRESENCE
            val counter: UInt = 1u

            val rpIdHash = sha256(APPLICATION.toByteArray(Charsets.UTF_8))
            val challengeHash = sha256(dataToSign)
            val authData = rpIdHash + byteArrayOf(flags) + uint32BigEndian(counter) + challengeHash

            val rawSignature = when (algorithm) {
                SkAlgorithm.ED25519 -> {
                    val signer = Signature.getInstance("Ed25519")
                    signer.initSign(privateKey)
                    signer.update(authData)
                    signer.sign()
                }

                SkAlgorithm.ECDSA_P256 -> {
                    val signer = Signature.getInstance("SHA256withECDSA")
                    signer.initSign(privateKey)
                    signer.update(authData)
                    signer.sign() // DER-encoded SEQUENCE { INTEGER r, INTEGER s }
                }
            }

            return SkSignatureBlob.pack(algorithm, rawSignature, flags, counter)
        }

        override suspend fun onPasswordNeeded(): String? = null
        override suspend fun onKeyboardInteractivePrompt(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
        ): List<String>? = null

        private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun uint32BigEndian(value: UInt): ByteArray {
            val i = value.toInt()
            return byteArrayOf(
                (i ushr 24).toByte(),
                (i ushr 16).toByte(),
                (i ushr 8).toByte(),
                i.toByte(),
            )
        }
    }
}
