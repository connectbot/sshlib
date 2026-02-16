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

package org.connectbot.sshlib.crypto

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class SignatureGenerationTest {

    private fun readKey(resourcePath: String): String = javaClass.getResourceAsStream("/keys/$resourcePath")!!
        .bufferedReader().readText()

    private fun signAndVerify(privateKey: SshPrivateKey): Boolean {
        val data = "test data to sign".toByteArray()

        val sigEntry = SignatureEntry.fromSshName(privateKey.signatureAlgorithm)
            ?: error("Unknown algorithm: ${privateKey.signatureAlgorithm}")

        val signatureBlob = sigEntry.algorithm.sign(
            privateKey.signatureAlgorithm,
            privateKey.jcaKeyPair.private,
            data
        )

        val pubKeyBlob = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)

        val pubKey = SshPublicKey(ByteBufferKaitaiStream(pubKeyBlob))
        pubKey._read()

        val sig = SshSignature(ByteBufferKaitaiStream(signatureBlob))
        sig._read()

        return sigEntry.algorithm.verify(pubKey, sig, data)
    }

    @Test
    fun `Ed25519 sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ed25519_unencrypted"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `ECDSA-256 sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ecdsa256_unencrypted"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `ECDSA-384 sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ecdsa384_unencrypted"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `ECDSA-521 sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ecdsa521_unencrypted"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `RSA sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("rsa_unencrypted"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `RSA SHA-256 sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("rsa_unencrypted"))
        // Override to use rsa-sha2-256
        val rsaSha256Key = SshPrivateKey(key.keyType, key.jcaKeyPair, "rsa-sha2-256")
        assertTrue(signAndVerify(rsaSha256Key))
    }

    @Test
    fun `PEM RSA sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("rsa_pem_unencrypted.pem"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `PEM EC sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ec_pem_unencrypted.pem"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `PKCS8 Ed25519 sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ed25519_pkcs8.pem"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `PKCS8 EC sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ec_pkcs8.pem"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `PKCS8 RSA sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("rsa_pkcs8.pem"))
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `encrypted OpenSSH key sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("ed25519_encrypted"), "testpass")
        assertTrue(signAndVerify(key))
    }

    @Test
    fun `encrypted PEM key sign and verify roundtrip`() {
        val key = PrivateKeyReader.read(readKey("rsa_pem_encrypted.pem"), "testpass")
        assertTrue(signAndVerify(key))
    }
}
