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
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OpenSshKeyWriterTest {

    private fun readKey(resourcePath: String): String = javaClass.getResourceAsStream("/keys/$resourcePath")!!
        .bufferedReader().readText()

    private fun roundTrip(keyResource: String, passphrase: String? = null) {
        val original = PrivateKeyReader.read(readKey(keyResource), passphrase).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original)
        assertTrue(encoded.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        val decoded = PrivateKeyReader.read(encoded).jcaKeyPair
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `round-trip Ed25519 unencrypted`() {
        roundTrip("ed25519_unencrypted")
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
    fun `round-trip RSA unencrypted`() {
        roundTrip("rsa_unencrypted")
    }

    @Test
    fun `round-trip Ed25519 encrypted`() {
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original, "testpass")
        assertTrue(PrivateKeyReader.isEncrypted(encoded))
        val decoded = PrivateKeyReader.read(encoded, "testpass").jcaKeyPair
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `round-trip RSA encrypted`() {
        val original = PrivateKeyReader.read(readKey("rsa_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original, "testpass")
        assertTrue(PrivateKeyReader.isEncrypted(encoded))
        val decoded = PrivateKeyReader.read(encoded, "testpass").jcaKeyPair
        assertEquals(
            (original.public as RSAPublicKey).modulus,
            (decoded.public as RSAPublicKey).modulus,
        )
    }

    @Test
    fun `round-trip ECDSA encrypted`() {
        val original = PrivateKeyReader.read(readKey("ecdsa256_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original, "testpass")
        assertTrue(PrivateKeyReader.isEncrypted(encoded))
        val decoded = PrivateKeyReader.read(encoded, "testpass").jcaKeyPair
        assertEquals(
            (original.public as ECPublicKey).w,
            (decoded.public as ECPublicKey).w,
        )
    }
}
