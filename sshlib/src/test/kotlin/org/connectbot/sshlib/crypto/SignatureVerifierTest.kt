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

    private fun signData(data: ByteArray, jcaAlgorithm: String, kp: java.security.KeyPair): ByteArray {
        val sig = Signature.getInstance(jcaAlgorithm)
        sig.initSign(kp.private)
        sig.update(data)
        return sig.sign()
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
}
