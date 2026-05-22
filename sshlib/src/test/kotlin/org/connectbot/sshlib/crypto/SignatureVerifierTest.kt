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

package org.connectbot.sshlib.crypto

import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SignatureVerifierTest {

    private fun encodeString(out: DataOutputStream, value: ByteArray) {
        out.writeInt(value.size)
        out.write(value)
    }

    private fun encodeString(out: DataOutputStream, value: String) = encodeString(out, value.toByteArray(Charsets.US_ASCII))

    private fun encodeMpint(out: DataOutputStream, value: BigInteger) {
        val bytes = value.toByteArray()
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun buildRsaHostKey(pub: RSAPublicKey): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, "ssh-rsa")
        encodeMpint(out, pub.publicExponent)
        encodeMpint(out, pub.modulus)
        return buf.toByteArray()
    }

    private fun buildSignatureBlob(algorithmName: String, sigBytes: ByteArray): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, algorithmName)
        encodeString(out, sigBytes)
        return buf.toByteArray()
    }

    private fun buildUnknownHostKey(algorithmName: String = "unknown-key@example.com"): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, algorithmName)
        encodeString(out, byteArrayOf(1, 2, 3))
        return buf.toByteArray()
    }

    private fun signData(data: ByteArray, jcaAlgorithm: String, kp: java.security.KeyPair): ByteArray {
        val sig = Signature.getInstance(jcaAlgorithm)
        sig.initSign(kp.private)
        sig.update(data)
        return sig.sign()
    }

    private fun readKey(resourcePath: String): SshPrivateKey {
        val data = requireNotNull(javaClass.getResourceAsStream("/keys/$resourcePath")) {
            "Missing test key resource: /keys/$resourcePath"
        }.use { stream ->
            stream.bufferedReader().use { reader -> reader.readText() }
        }
        return PrivateKeyReader.read(data)
    }

    private fun signWithSshAlgorithm(privateKey: SshPrivateKey, algorithmName: String, data: ByteArray): ByteArray {
        val entry = SignatureEntry.fromSshName(algorithmName) ?: error("Unknown algorithm: $algorithmName")
        return entry.algorithm.sign(algorithmName, privateKey.jcaKeyPair.private, data)
    }

    @Test
    fun `accepts rsa-sha2-256 signature when rsa-sha2-256 was negotiated`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        val sigBytes = signData(data, "SHA256withRSA", kp)
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("rsa-sha2-256", sigBytes)

        assertTrue(SignatureVerifier.verify(hostKey, sigBlob, data, "rsa-sha2-256"))
    }

    @Test
    fun `accepts rsa-sha2-512 signature when rsa-sha2-512 was negotiated`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        val sigBytes = signData(data, "SHA512withRSA", kp)
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("rsa-sha2-512", sigBytes)

        assertTrue(SignatureVerifier.verify(hostKey, sigBlob, data, "rsa-sha2-512"))
    }

    @Test
    fun `rejects ssh-rsa signature blob when rsa-sha2-256 was negotiated`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        // Server signs correctly with SHA-1, but client negotiated SHA-256
        val sigBytes = signData(data, "SHA1withRSA", kp)
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("ssh-rsa", sigBytes)

        assertFalse(SignatureVerifier.verify(hostKey, sigBlob, data, "rsa-sha2-256"))
    }

    @Test
    fun `rejects rsa-sha2-256 signature blob when rsa-sha2-512 was negotiated`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        val sigBytes = signData(data, "SHA256withRSA", kp)
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("rsa-sha2-256", sigBytes)

        assertFalse(SignatureVerifier.verify(hostKey, sigBlob, data, "rsa-sha2-512"))
    }

    @Test
    fun `rejects rsa-sha2-512 signature blob when rsa-sha2-256 was negotiated`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        val sigBytes = signData(data, "SHA512withRSA", kp)
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("rsa-sha2-512", sigBytes)

        assertFalse(SignatureVerifier.verify(hostKey, sigBlob, data, "rsa-sha2-256"))
    }

    @Test
    fun `rejects completely wrong algorithm name in signature blob`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        val sigBytes = signData(data, "SHA256withRSA", kp)
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("unknown-algo", sigBytes)

        assertFalse(SignatureVerifier.verify(hostKey, sigBlob, data, "rsa-sha2-256"))
    }

    @Test
    fun `rejects negotiated unknown signature algorithm`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val data = "exchange hash".toByteArray()
        val hostKey = buildRsaHostKey(kp.public as RSAPublicKey)
        val sigBlob = buildSignatureBlob("unknown-algo", byteArrayOf(1, 2, 3))

        assertFalse(SignatureVerifier.verify(hostKey, sigBlob, data, "unknown-algo"))
    }

    @Test
    fun `verifyWithKeyType accepts RSA-compatible signature algorithms`() {
        val privateKey = readKey("rsa_unencrypted")
        val data = "session binding".toByteArray()
        val hostKey = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)

        for (algorithmName in listOf("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512")) {
            val sigBlob = signWithSshAlgorithm(privateKey, algorithmName, data)

            assertTrue(SignatureVerifier.verifyWithKeyType(hostKey, sigBlob, data), algorithmName)
        }
    }

    @Test
    fun `verifyWithKeyType accepts matching Ed25519 signature algorithm`() {
        val privateKey = readKey("ed25519_unencrypted")
        val data = "session binding".toByteArray()
        val hostKey = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)
        val sigBlob = signWithSshAlgorithm(privateKey, "ssh-ed25519", data)

        assertTrue(SignatureVerifier.verifyWithKeyType(hostKey, sigBlob, data))
    }

    @Test
    fun `verifyWithKeyType rejects signature algorithm incompatible with key type`() {
        val privateKey = readKey("ed25519_unencrypted")
        val rsaKey = readKey("rsa_unencrypted")
        val data = "session binding".toByteArray()
        val ed25519HostKey = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)
        val rsaSigBlob = signWithSshAlgorithm(rsaKey, "rsa-sha2-256", data)

        assertFalse(SignatureVerifier.verifyWithKeyType(ed25519HostKey, rsaSigBlob, data))
    }

    @Test
    fun `verifyWithKeyType rejects non-RSA signature algorithm for RSA key`() {
        val rsaKey = readKey("rsa_unencrypted")
        val ed25519Key = readKey("ed25519_unencrypted")
        val data = "session binding".toByteArray()
        val rsaHostKey = SshPublicKeyEncoder.encode(rsaKey.jcaKeyPair, rsaKey.keyType)
        val ed25519SigBlob = signWithSshAlgorithm(ed25519Key, "ssh-ed25519", data)

        assertFalse(SignatureVerifier.verifyWithKeyType(rsaHostKey, ed25519SigBlob, data))
    }

    @Test
    fun `verifyWithKeyType rejects unknown self-described signature algorithm`() {
        val data = "session binding".toByteArray()
        val hostKey = buildUnknownHostKey()
        val sigBlob = buildSignatureBlob("unknown-key@example.com", byteArrayOf(4, 5, 6))

        assertFalse(SignatureVerifier.verifyWithKeyType(hostKey, sigBlob, data))
    }
}
