/*
 * ConnectBot SSH Library
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

import org.connectbot.sshlib.transport.TransportException
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class ChaCha20Poly1305CipherTest {

    // RFC 8439 Section 2.5.2 Poly1305 test vector
    @Test
    fun `Poly1305 RFC 8439 test vector`() {
        val key = hexToBytes(
            "85d6be7857556d337f4452fe42d506a8" +
                "0103808afb0db2fd4abff6af4149f51b",
        )
        val message = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
        val expectedTag = hexToBytes("a8061dc1305136c6c22b8baf0c0127a9")

        val poly = Poly1305()
        poly.init(key)
        poly.update(message, 0, message.size)
        val tag = ByteArray(16)
        poly.finish(tag, 0)

        assertContentEquals(expectedTag, tag)
    }

    @Test
    fun `Poly1305 with multi-block input`() {
        val key = hexToBytes(
            "85d6be7857556d337f4452fe42d506a8" +
                "0103808afb0db2fd4abff6af4149f51b",
        )
        val message = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)

        val poly1 = Poly1305()
        poly1.init(key)
        poly1.update(message, 0, message.size)
        val tag1 = ByteArray(16)
        poly1.finish(tag1, 0)

        // Feed byte-by-byte to test buffering
        val poly2 = Poly1305()
        poly2.init(key)
        for (b in message) {
            poly2.update(byteArrayOf(b), 0, 1)
        }
        val tag2 = ByteArray(16)
        poly2.finish(tag2, 0)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `length encryption roundtrip`() {
        val key = ByteArray(64).apply {
            for (i in indices) this[i] = i.toByte()
        }
        val encCipher = ChaCha20Poly1305Cipher(key)
        val decCipher = ChaCha20Poly1305Cipher(key)

        val plainLength = byteArrayOf(0x00, 0x00, 0x00, 0x14) // 20 bytes
        val seqNum = 42L

        val encrypted = encCipher.encryptLength(seqNum, plainLength)
        val decrypted = decCipher.decryptLength(seqNum, encrypted)

        assertContentEquals(plainLength, decrypted)
    }

    @Test
    fun `encrypt and decrypt roundtrip`() {
        val key = ByteArray(64).apply {
            for (i in indices) this[i] = i.toByte()
        }
        val encCipher = ChaCha20Poly1305Cipher(key)
        val decCipher = ChaCha20Poly1305Cipher(key)

        val seqNum = 1L
        val plainLength = byteArrayOf(0x00, 0x00, 0x00, 0x20)
        val plaintext = ByteArray(32) { (it * 3).toByte() }

        val encryptedLength = encCipher.encryptLength(seqNum, plainLength)
        val result = encCipher.encrypt(encryptedLength, plaintext)

        decCipher.decryptLength(seqNum, encryptedLength)
        val decrypted = decCipher.decrypt(encryptedLength, result.ciphertext, result.tag)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `tag verification failure on modified ciphertext`() {
        val key = ByteArray(64).apply {
            for (i in indices) this[i] = i.toByte()
        }
        val encCipher = ChaCha20Poly1305Cipher(key)
        val decCipher = ChaCha20Poly1305Cipher(key)

        val seqNum = 5L
        val plainLength = byteArrayOf(0x00, 0x00, 0x00, 0x10)
        val plaintext = ByteArray(16) { it.toByte() }

        val encryptedLength = encCipher.encryptLength(seqNum, plainLength)
        val result = encCipher.encrypt(encryptedLength, plaintext)

        // Tamper with ciphertext
        val tampered = result.ciphertext.clone()
        tampered[0] = (tampered[0].toInt() xor 0xff).toByte()

        decCipher.decryptLength(seqNum, encryptedLength)
        assertFailsWith<TransportException> {
            decCipher.decrypt(encryptedLength, tampered, result.tag)
        }
    }

    @Test
    fun `tag verification failure on modified tag`() {
        val key = ByteArray(64).apply {
            for (i in indices) this[i] = i.toByte()
        }
        val encCipher = ChaCha20Poly1305Cipher(key)
        val decCipher = ChaCha20Poly1305Cipher(key)

        val seqNum = 7L
        val plainLength = byteArrayOf(0x00, 0x00, 0x00, 0x10)
        val plaintext = ByteArray(16) { it.toByte() }

        val encryptedLength = encCipher.encryptLength(seqNum, plainLength)
        val result = encCipher.encrypt(encryptedLength, plaintext)

        // Tamper with tag
        val tamperedTag = result.tag.clone()
        tamperedTag[0] = (tamperedTag[0].toInt() xor 0xff).toByte()

        decCipher.decryptLength(seqNum, encryptedLength)
        assertFailsWith<TransportException> {
            decCipher.decrypt(encryptedLength, result.ciphertext, tamperedTag)
        }
    }

    @Test
    fun `encryptsLength returns true`() {
        val key = ByteArray(64)
        val cipher = ChaCha20Poly1305Cipher(key)
        assertEquals(true, cipher.encryptsLength)
    }

    @Test
    fun `tagLength returns 16`() {
        val key = ByteArray(64)
        val cipher = ChaCha20Poly1305Cipher(key)
        assertEquals(16, cipher.tagLength)
    }

    @Test
    fun `rejects invalid key size`() {
        assertFailsWith<IllegalArgumentException> {
            ChaCha20Poly1305Cipher(ByteArray(32))
        }
    }

    @Test
    fun `multiple packets with incrementing sequence numbers`() {
        val key = ByteArray(64).apply {
            for (i in indices) this[i] = (i * 7).toByte()
        }
        val encCipher = ChaCha20Poly1305Cipher(key)
        val decCipher = ChaCha20Poly1305Cipher(key)

        for (seq in 0L..5L) {
            val plainLength = byteArrayOf(0x00, 0x00, 0x00, 0x08)
            val plaintext = ByteArray(8) { (it + seq.toInt()).toByte() }

            val encLen = encCipher.encryptLength(seq, plainLength)
            val result = encCipher.encrypt(encLen, plaintext)

            decCipher.decryptLength(seq, encLen)
            val decrypted = decCipher.decrypt(encLen, result.ciphertext, result.tag)

            assertContentEquals(plaintext, decrypted, "Failed at seq=$seq")
        }
    }

    @Test
    fun `different sequence numbers produce different ciphertext`() {
        val key = ByteArray(64).apply { for (i in indices) this[i] = i.toByte() }
        val cipher1 = ChaCha20Poly1305Cipher(key)
        val cipher2 = ChaCha20Poly1305Cipher(key)
        val plaintext = ByteArray(16) { 0x42 }
        val plainLength = byteArrayOf(0, 0, 0, 16)

        val enc1 = cipher1.encryptLength(0L, plainLength)
        val result1 = cipher1.encrypt(enc1, plaintext)

        val enc2 = cipher2.encryptLength(1L, plainLength)
        val result2 = cipher2.encrypt(enc2, plaintext)

        assertFalse(result1.ciphertext.contentEquals(result2.ciphertext), "Different seq nums must produce different ciphertext")
    }

    @Test
    fun `all four sequence number bytes influence the nonce`() {
        // updateNonce writes bytes 8-11 of the 12-byte nonce from seqNum bits 31-0.
        // If any of the four shift expressions (ushr 24, ushr 16, ushr 8, plain) were
        // replaced with a shift-left (a pitest mutation), two otherwise-identical
        // encryptions that differ only in the affected byte position would produce
        // the same ciphertext, failing this test.
        val key = ByteArray(64).apply { for (i in indices) this[i] = i.toByte() }
        val plainLength = byteArrayOf(0, 0, 0, 8)
        val plaintext = ByteArray(8) { it.toByte() }

        // Pairs where only one byte position of the nonce differs.
        // seqNum 0x00000001 vs 0x00000100 differ in byte 3 vs byte 2 of the nonce.
        // seqNum 0x00000001 vs 0x00010000 differ in byte 3 vs byte 1.
        // seqNum 0x00000001 vs 0x01000000 differ in byte 3 vs byte 0.
        val seqNums = listOf(0x00000001L, 0x00000100L, 0x00010000L, 0x01000000L)

        val ciphertexts = seqNums.map { seqNum ->
            val cipher = ChaCha20Poly1305Cipher(key)
            val encLen = cipher.encryptLength(seqNum, plainLength)
            cipher.encrypt(encLen, plaintext).ciphertext
        }

        // Every pair must produce distinct ciphertext — if any nonce byte assignment
        // is wrong (e.g. ushr replaced with shl) two entries will collide.
        for (i in ciphertexts.indices) {
            for (j in i + 1 until ciphertexts.size) {
                assertFalse(
                    ciphertexts[i].contentEquals(ciphertexts[j]),
                    "seqNums 0x${seqNums[i].toString(16)} and 0x${seqNums[j].toString(16)} produced identical ciphertext",
                )
            }
        }
    }

    @Test
    fun `destroy zeroes key material`() {
        val key = ByteArray(64).apply { for (i in indices) this[i] = (i + 1).toByte() }
        val cipher = ChaCha20Poly1305Cipher(key)
        cipher.destroy()
        assertContentEquals(ByteArray(64), key)
    }

    @Test
    fun `constantTimeEquals is size-sensitive - different length returns false`() {
        val key = ByteArray(64)
        val enc = ChaCha20Poly1305Cipher(key)
        val dec = ChaCha20Poly1305Cipher(key)
        val plainLength = byteArrayOf(0, 0, 0, 1)
        val plaintext = byteArrayOf(0x42)

        val encLen = enc.encryptLength(0L, plainLength)
        val result = enc.encrypt(encLen, plaintext)

        // A tag with correct bytes but wrong length would be caught by constantTimeEquals size check;
        // verify the cipher correctly rejects a tag of different length by providing wrong data
        dec.decryptLength(0L, encLen)
        assertFailsWith<TransportException> {
            // Pass a 15-byte tag instead of 16
            dec.decrypt(encLen, result.ciphertext, result.tag.copyOf(15))
        }
    }

    private fun hexToBytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
