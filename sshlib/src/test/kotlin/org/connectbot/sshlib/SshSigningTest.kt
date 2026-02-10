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

package org.connectbot.sshlib

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.crypto.PrivateKeyReader
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.crypto.SignatureVerifier
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SshSigningTest {

    private fun readKey(resourcePath: String): String {
        return javaClass.getResourceAsStream("/keys/$resourcePath")!!
            .bufferedReader().readText()
    }

    private fun signAndVerify(algorithmName: String, keyResource: String, passphrase: String? = null) {
        val keyData = readKey(keyResource)
        val data = "test data for auth handler".toByteArray()

        val signature = SshSigning.sign(algorithmName, keyData, passphrase, data)
        assertTrue(signature.isNotEmpty())

        val sigEntry = SignatureEntry.fromSshName(algorithmName)!!

        val pubKey = SshSigning.getPublicKey(algorithmName, keyData, passphrase)
        assertEquals(algorithmName, pubKey.algorithmName)
        assertTrue(pubKey.publicKeyBlob.isNotEmpty())

        val parsedPubKey = SshPublicKey(ByteBufferKaitaiStream(pubKey.publicKeyBlob))
        parsedPubKey._read()
        val parsedSig = SshSignature(ByteBufferKaitaiStream(signature))
        parsedSig._read()

        assertTrue(sigEntry.algorithm.verify(parsedPubKey, parsedSig, data))
    }

    @Test
    fun `Ed25519 sign produces valid signature`() {
        signAndVerify("ssh-ed25519", "ed25519_unencrypted")
    }

    @Test
    fun `ECDSA-256 sign produces valid signature`() {
        signAndVerify("ecdsa-sha2-nistp256", "ecdsa256_unencrypted")
    }

    @Test
    fun `RSA SHA-256 sign produces valid signature`() {
        signAndVerify("rsa-sha2-256", "rsa_unencrypted")
    }

    @Test
    fun `RSA SHA-512 sign produces valid signature`() {
        signAndVerify("rsa-sha2-512", "rsa_unencrypted")
    }

    @Test
    fun `sign with byte array overload`() {
        val keyData = readKey("ed25519_unencrypted").toByteArray()
        val data = "test data".toByteArray()

        val signature = SshSigning.sign("ssh-ed25519", keyData, null, data)
        assertTrue(signature.isNotEmpty())
    }

    @Test
    fun `sign with encrypted key`() {
        signAndVerify("ssh-ed25519", "ed25519_encrypted", "testpass")
    }

    @Test
    fun `getPublicKey with byte array overload`() {
        val keyData = readKey("ed25519_unencrypted").toByteArray()
        val pubKey = SshSigning.getPublicKey("ssh-ed25519", keyData, null)
        assertEquals("ssh-ed25519", pubKey.algorithmName)
        assertTrue(pubKey.publicKeyBlob.isNotEmpty())
    }

    @Test(expected = SshException::class)
    fun `sign with unknown algorithm throws`() {
        val keyData = readKey("ed25519_unencrypted")
        SshSigning.sign("unknown-algorithm", keyData, null, "data".toByteArray())
    }

    private fun loadKeyPair(keyResource: String, passphrase: String? = null): java.security.KeyPair {
        val keyData = readKey(keyResource)
        return PrivateKeyReader.read(keyData, passphrase).jcaKeyPair
    }

    @Test
    fun `encodePublicKey Ed25519 from KeyPair`() {
        val keyPair = loadKeyPair("ed25519_unencrypted")
        val authPubKey = SshSigning.encodePublicKey(keyPair)
        assertEquals("ssh-ed25519", authPubKey.algorithmName)

        val fromPrivate = SshSigning.getPublicKey("ssh-ed25519", readKey("ed25519_unencrypted"), null)
        assertEquals(fromPrivate, authPubKey)
    }

    @Test
    fun `encodePublicKey ECDSA-256 from KeyPair`() {
        val keyPair = loadKeyPair("ecdsa256_unencrypted")
        val authPubKey = SshSigning.encodePublicKey(keyPair)
        assertEquals("ecdsa-sha2-nistp256", authPubKey.algorithmName)

        val fromPrivate = SshSigning.getPublicKey("ecdsa-sha2-nistp256", readKey("ecdsa256_unencrypted"), null)
        assertEquals(fromPrivate, authPubKey)
    }

    @Test
    fun `encodePublicKey ECDSA-384 from KeyPair`() {
        val keyPair = loadKeyPair("ecdsa384_unencrypted")
        val authPubKey = SshSigning.encodePublicKey(keyPair)
        assertEquals("ecdsa-sha2-nistp384", authPubKey.algorithmName)
    }

    @Test
    fun `encodePublicKey ECDSA-521 from KeyPair`() {
        val keyPair = loadKeyPair("ecdsa521_unencrypted")
        val authPubKey = SshSigning.encodePublicKey(keyPair)
        assertEquals("ecdsa-sha2-nistp521", authPubKey.algorithmName)
    }

    @Test
    fun `encodePublicKey RSA from KeyPair`() {
        val keyPair = loadKeyPair("rsa_unencrypted")
        val authPubKey = SshSigning.encodePublicKey(keyPair)
        assertEquals("ssh-rsa", authPubKey.algorithmName)

        val fromPrivate = SshSigning.getPublicKey("ssh-rsa", readKey("rsa_unencrypted"), null)
        assertEquals(fromPrivate, authPubKey)
    }

    @Test(expected = SshException::class)
    fun `encodePublicKey unsupported key type throws`() {
        val kpg = KeyPairGenerator.getInstance("DSA")
        kpg.initialize(2048)
        SshSigning.encodePublicKey(kpg.generateKeyPair())
    }

    @Test
    fun `signWithKeyPair Ed25519 produces valid signature`() {
        val keyPair = loadKeyPair("ed25519_unencrypted")
        val data = "test data for keypair signing".toByteArray()

        val signature = SshSigning.signWithKeyPair("ssh-ed25519", keyPair, data)
        assertTrue(signature.isNotEmpty())

        val sigEntry = SignatureEntry.fromSshName("ssh-ed25519")!!
        val pubKey = SshSigning.encodePublicKey(keyPair)
        val parsedPubKey = SshPublicKey(ByteBufferKaitaiStream(pubKey.publicKeyBlob))
        parsedPubKey._read()
        val parsedSig = SshSignature(ByteBufferKaitaiStream(signature))
        parsedSig._read()

        assertTrue(sigEntry.algorithm.verify(parsedPubKey, parsedSig, data))
    }

    @Test
    fun `signWithKeyPair ECDSA-256 produces valid signature`() {
        val keyPair = loadKeyPair("ecdsa256_unencrypted")
        val data = "test data for keypair signing".toByteArray()

        val signature = SshSigning.signWithKeyPair("ecdsa-sha2-nistp256", keyPair, data)
        assertTrue(signature.isNotEmpty())

        val sigEntry = SignatureEntry.fromSshName("ecdsa-sha2-nistp256")!!
        val pubKey = SshSigning.encodePublicKey(keyPair)
        val parsedPubKey = SshPublicKey(ByteBufferKaitaiStream(pubKey.publicKeyBlob))
        parsedPubKey._read()
        val parsedSig = SshSignature(ByteBufferKaitaiStream(signature))
        parsedSig._read()

        assertTrue(sigEntry.algorithm.verify(parsedPubKey, parsedSig, data))
    }

    @Test
    fun `signWithKeyPair RSA SHA-256 produces valid signature`() {
        val keyPair = loadKeyPair("rsa_unencrypted")
        val data = "test data for keypair signing".toByteArray()

        val signature = SshSigning.signWithKeyPair("rsa-sha2-256", keyPair, data)
        assertTrue(signature.isNotEmpty())

        val sigEntry = SignatureEntry.fromSshName("rsa-sha2-256")!!
        val pubKey = SshSigning.encodePublicKey(keyPair)
        val parsedPubKey = SshPublicKey(ByteBufferKaitaiStream(pubKey.publicKeyBlob))
        parsedPubKey._read()
        val parsedSig = SshSignature(ByteBufferKaitaiStream(signature))
        parsedSig._read()

        assertTrue(sigEntry.algorithm.verify(parsedPubKey, parsedSig, data))
    }

    @Test
    fun `signWithKeyPair RSA SHA-512 produces valid signature`() {
        val keyPair = loadKeyPair("rsa_unencrypted")
        val data = "test data for keypair signing".toByteArray()

        val signature = SshSigning.signWithKeyPair("rsa-sha2-512", keyPair, data)
        assertTrue(signature.isNotEmpty())

        val sigEntry = SignatureEntry.fromSshName("rsa-sha2-512")!!
        val pubKey = SshSigning.encodePublicKey(keyPair)
        val parsedPubKey = SshPublicKey(ByteBufferKaitaiStream(pubKey.publicKeyBlob))
        parsedPubKey._read()
        val parsedSig = SshSignature(ByteBufferKaitaiStream(signature))
        parsedSig._read()

        assertTrue(sigEntry.algorithm.verify(parsedPubKey, parsedSig, data))
    }

    @Test(expected = SshException::class)
    fun `signWithKeyPair unknown algorithm throws`() {
        val keyPair = loadKeyPair("ed25519_unencrypted")
        SshSigning.signWithKeyPair("unknown-algorithm", keyPair, "data".toByteArray())
    }

    @Test
    fun `encodePublicKeyBlob Ed25519 matches encodePublicKey`() {
        val keyPair = loadKeyPair("ed25519_unencrypted")
        val blob = SshSigning.encodePublicKeyBlob(keyPair.public)
        val expected = SshSigning.encodePublicKey(keyPair).publicKeyBlob
        assertTrue(blob.contentEquals(expected))
    }

    @Test
    fun `encodePublicKeyBlob ECDSA-256 matches encodePublicKey`() {
        val keyPair = loadKeyPair("ecdsa256_unencrypted")
        val blob = SshSigning.encodePublicKeyBlob(keyPair.public)
        val expected = SshSigning.encodePublicKey(keyPair).publicKeyBlob
        assertTrue(blob.contentEquals(expected))
    }

    @Test
    fun `encodePublicKeyBlob RSA matches encodePublicKey`() {
        val keyPair = loadKeyPair("rsa_unencrypted")
        val blob = SshSigning.encodePublicKeyBlob(keyPair.public)
        val expected = SshSigning.encodePublicKey(keyPair).publicKeyBlob
        assertTrue(blob.contentEquals(expected))
    }
}

class AuthPublicKeyTest {

    @Test
    fun `equal keys are equal`() {
        val blob = byteArrayOf(1, 2, 3)
        val a = AuthPublicKey("ssh-ed25519", blob.copyOf())
        val b = AuthPublicKey("ssh-ed25519", blob.copyOf())
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `different algorithm names are not equal`() {
        val blob = byteArrayOf(1, 2, 3)
        val a = AuthPublicKey("ssh-ed25519", blob.copyOf())
        val b = AuthPublicKey("rsa-sha2-256", blob.copyOf())
        assertNotEquals(a, b)
    }

    @Test
    fun `different blobs are not equal`() {
        val a = AuthPublicKey("ssh-ed25519", byteArrayOf(1, 2, 3))
        val b = AuthPublicKey("ssh-ed25519", byteArrayOf(4, 5, 6))
        assertNotEquals(a, b)
    }

    @Test
    fun `same instance is equal`() {
        val key = AuthPublicKey("ssh-ed25519", byteArrayOf(1, 2, 3))
        assertEquals(key, key)
    }

    @Test
    fun `not equal to null`() {
        val key = AuthPublicKey("ssh-ed25519", byteArrayOf(1, 2, 3))
        assertFalse(key.equals(null))
    }

    @Test
    fun `not equal to different type`() {
        val key = AuthPublicKey("ssh-ed25519", byteArrayOf(1, 2, 3))
        assertFalse(key.equals("string"))
    }
}
