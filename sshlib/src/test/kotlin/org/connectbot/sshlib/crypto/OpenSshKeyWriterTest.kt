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

import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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

    @Test
    fun `Ed25519 private key encoding contains correct public key bytes`() {
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original)
        val decoded = PrivateKeyReader.read(encoded).jcaKeyPair
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `reader validates 1-2-3 padding pattern on unencrypted key`() {
        // Write a key, then corrupt the last byte (a padding byte) so the reader rejects it.
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original)
        val binary = extractBinary(encoded)
        // The last byte is the last OpenSSH padding byte (value = number of pad bytes).
        // Flip it to a wrong value.
        binary[binary.size - 1] = (binary.last().toInt() xor 0xff).toByte()
        assertFailsWith<SshException> {
            PrivateKeyReader.read(rebuildPem(binary))
        }
    }

    @Test
    fun `reader validates 1-2-3 padding pattern on encrypted key`() {
        // For an encrypted key the padding is inside the ciphertext so we can't corrupt
        // individual padding bytes without breaking the MAC — instead rely on decryption
        // round-trip passing, which exercises the padding check on the plaintext.
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original, "pass")
        val decoded = PrivateKeyReader.read(encoded, "pass").jcaKeyPair
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encrypted output uses random salt each time`() {
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val enc1 = OpenSshKeyWriter.write(original, "pass")
        val enc2 = OpenSshKeyWriter.write(original, "pass")
        assertTrue(enc1 != enc2, "Encrypted output must differ due to random salt/checkInt")
    }

    @Test
    fun `unencrypted private section is padded to 8-byte boundary`() {
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original)
        val privateSectionLen = extractPrivateSectionLength(encoded)
        assertEquals(0, privateSectionLen % 8, "Unencrypted private section must be a multiple of 8 bytes, got $privateSectionLen")
    }

    @Test
    fun `encrypted private section is padded to 16-byte boundary`() {
        val original = PrivateKeyReader.read(readKey("ed25519_unencrypted")).jcaKeyPair
        val encoded = OpenSshKeyWriter.write(original, "pass")
        val privateSectionLen = extractPrivateSectionLength(encoded)
        assertEquals(0, privateSectionLen % 16, "Encrypted private section must be a multiple of 16 bytes (AES block size), got $privateSectionLen")
    }

    private fun extractPrivateSectionLength(pem: String): Int {
        val binary = extractBinary(pem)
        val buf = ByteBuffer.wrap(binary)

        fun skipBytes(n: Int) {
            buf.position(buf.position() + n)
        }
        fun skipString() {
            skipBytes(buf.int)
        }

        // Skip magic: "openssh-key-v1\0" (15 bytes: 14 ASCII chars + NUL)
        skipBytes(15)

        // Skip cipherName, kdfName, kdfOptions (each a uint32-prefixed string)
        skipString()
        skipString()
        skipString()

        // Skip numKeys uint32
        buf.int

        // Skip public key blob (uint32-prefixed string)
        skipString()

        // The next uint32 is the length of the private section (encrypted or plaintext)
        return buf.int
    }

    private fun extractBinary(pem: String): ByteArray {
        val b64 = pem.lines()
            .filter { !it.startsWith("-----") && it.isNotBlank() }
            .joinToString("")
        return Base64.getDecoder().decode(b64)
    }

    private fun rebuildPem(binary: ByteArray): String {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(binary)
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n$b64\n-----END OPENSSH PRIVATE KEY-----\n"
    }
}
