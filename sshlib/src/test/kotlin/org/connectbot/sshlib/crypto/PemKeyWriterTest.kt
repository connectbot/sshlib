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

import org.junit.Test
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.ECPublicKey
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PemKeyWriterTest {

    private fun readKey(resourcePath: String): String {
        return javaClass.getResourceAsStream("/keys/$resourcePath")!!
            .bufferedReader().readText()
    }

    private fun roundTrip(keyResource: String, passphrase: String? = null) {
        val original = PrivateKeyReader.read(readKey(keyResource), passphrase).jcaKeyPair
        val encoded = PemKeyWriter.write(original)
        val decoded = PrivateKeyReader.read(encoded).jcaKeyPair
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `round-trip RSA unencrypted`() {
        roundTrip("rsa_unencrypted")
    }

    @Test
    fun `round-trip RSA from PEM`() {
        roundTrip("rsa_pem_unencrypted.pem")
    }

    @Test
    fun `round-trip ECDSA-256 unencrypted`() {
        roundTrip("ecdsa256_unencrypted")
    }

    @Test
    fun `round-trip ECDSA-384 unencrypted`() {
        roundTrip("ecdsa384_unencrypted")
    }

    @Test
    fun `round-trip ECDSA-521 unencrypted`() {
        roundTrip("ecdsa521_unencrypted")
    }

    @Test
    fun `round-trip Ed25519 unencrypted`() {
        roundTrip("ed25519_unencrypted")
    }

    @Test
    fun `round-trip RSA encrypted`() {
        val original = PrivateKeyReader.read(readKey("rsa_unencrypted")).jcaKeyPair
        val encoded = PemKeyWriter.write(original, "testpass")
        assertTrue(encoded.contains("ENCRYPTED"))
        assertTrue(encoded.contains("DEK-Info"))
        val decoded = PrivateKeyReader.read(encoded, "testpass").jcaKeyPair
        assertEquals(
            (original.public as RSAPublicKey).modulus,
            (decoded.public as RSAPublicKey).modulus
        )
    }

    @Test
    fun `round-trip EC encrypted`() {
        val original = PrivateKeyReader.read(readKey("ecdsa256_unencrypted")).jcaKeyPair
        val encoded = PemKeyWriter.write(original, "testpass")
        assertTrue(encoded.contains("ENCRYPTED"))
        val decoded = PrivateKeyReader.read(encoded, "testpass").jcaKeyPair
        assertEquals(
            (original.public as ECPublicKey).w,
            (decoded.public as ECPublicKey).w
        )
    }

    @Test
    fun `RSA output contains correct PEM markers`() {
        val keyPair = PrivateKeyReader.read(readKey("rsa_unencrypted")).jcaKeyPair
        val pem = PemKeyWriter.write(keyPair)
        assertTrue(pem.contains("-----BEGIN RSA PRIVATE KEY-----"))
        assertTrue(pem.contains("-----END RSA PRIVATE KEY-----"))
    }

    @Test
    fun `EC output contains correct PEM markers`() {
        val keyPair = PrivateKeyReader.read(readKey("ecdsa256_unencrypted")).jcaKeyPair
        val pem = PemKeyWriter.write(keyPair)
        assertTrue(pem.contains("-----BEGIN EC PRIVATE KEY-----"))
        assertTrue(pem.contains("-----END EC PRIVATE KEY-----"))
    }

    @Test
    fun `Ed25519 output contains PKCS8 PEM markers`() {
        val keyPair = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val pem = PemKeyWriter.write(keyPair)
        assertTrue(pem.contains("-----BEGIN PRIVATE KEY-----"))
        assertTrue(pem.contains("-----END PRIVATE KEY-----"))
    }
}
