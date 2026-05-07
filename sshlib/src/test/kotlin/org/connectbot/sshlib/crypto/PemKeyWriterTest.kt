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

import org.junit.jupiter.api.Test
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PemKeyWriterTest {

    private fun readKey(resourcePath: String): String = javaClass.getResourceAsStream("/keys/$resourcePath")!!
        .bufferedReader().readText()

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
            (decoded.public as RSAPublicKey).modulus,
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
            (decoded.public as ECPublicKey).w,
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

    @Test
    fun `EC key private bytes are exactly fieldSize long in output`() {
        // Tests the padOrTrim logic in writeEc: the scalar s value from BigInteger.toByteArray()
        // may have a leading zero sign byte (size > fieldSize) or may be short (size < fieldSize).
        // Parse the produced DER and assert the private key OCTET STRING is exactly fieldSize bytes.
        val cases = listOf(
            "ecdsa256_unencrypted" to 32,
            "ecdsa384_unencrypted" to 48,
            "ecdsa521_unencrypted" to 66,
        )
        for ((key, expectedFieldSize) in cases) {
            val original = PrivateKeyReader.read(readKey(key)).jcaKeyPair
            val pem = PemKeyWriter.write(original)

            // Extract DER from PEM (SEC1 "EC PRIVATE KEY" format)
            val der = pem.lines()
                .filter { !it.startsWith("-----") && it.isNotBlank() }
                .joinToString("")
                .let { Base64.getDecoder().decode(it) }

            // SEC1 ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING,
            //   [0] OID OPTIONAL, [1] BIT STRING OPTIONAL }
            val privateKeyBytes = DerReader(der).readSequence { seq ->
                seq.readInteger() // version = 1
                val octets = seq.readOctetString() // the private scalar bytes
                // Skip optional context tags [0] and [1]
                while (seq.hasRemaining()) seq.skipTag()
                octets
            }
            assertEquals(
                expectedFieldSize,
                privateKeyBytes.size,
                "EC private scalar for $key must be exactly $expectedFieldSize bytes, got ${privateKeyBytes.size}",
            )
        }
    }

    @Test
    fun `wrapPem includes base64 content between markers`() {
        val keyPair = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val pem = PemKeyWriter.write(keyPair)
        val lines = pem.lines().filter { it.isNotBlank() }
        assertTrue(lines.size > 2, "PEM should have content between markers")
        val contentLines = lines.drop(1).dropLast(1)
        assertTrue(contentLines.isNotEmpty())
        contentLines.forEach { line ->
            assertTrue(line.matches(Regex("[A-Za-z0-9+/=]+")), "PEM content line is valid base64: $line")
        }
    }
}
