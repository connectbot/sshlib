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

import org.connectbot.sshlib.transport.TransportException
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.nio.ByteBuffer
import kotlin.test.assertFailsWith

class AesGcmCipherTest {

    private fun makeIv(fixedField: ByteArray = ByteArray(4), counter: Long = 0L): ByteArray {
        val iv = ByteArray(12)
        System.arraycopy(fixedField, 0, iv, 0, 4)
        ByteBuffer.wrap(iv, 4, 8).putLong(counter)
        return iv
    }

    private fun packetLengthBytes(length: Int): ByteArray = ByteBuffer.allocate(4).putInt(length).array()

    @Test
    fun roundTripAes128() {
        val key = ByteArray(16) { it.toByte() }
        val iv = makeIv()
        val plaintext = ByteArray(32) { (it + 0x41).toByte() }
        val packetLength = packetLengthBytes(plaintext.size)

        val encryptor = AesGcmCipher(key, iv)
        val decryptor = AesGcmCipher(key, iv.copyOf())

        val result = encryptor.encrypt(packetLength, plaintext)
        val decrypted = decryptor.decrypt(packetLength, result.ciphertext, result.tag)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun roundTripAes256() {
        val key = ByteArray(32) { it.toByte() }
        val iv = makeIv()
        val plaintext = ByteArray(48) { (it + 0x30).toByte() }
        val packetLength = packetLengthBytes(plaintext.size)

        val encryptor = AesGcmCipher(key, iv)
        val decryptor = AesGcmCipher(key, iv.copyOf())

        val result = encryptor.encrypt(packetLength, plaintext)
        val decrypted = decryptor.decrypt(packetLength, result.ciphertext, result.tag)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun tagLengthIs16() {
        val key = ByteArray(16) { it.toByte() }
        val iv = makeIv()
        val cipher = AesGcmCipher(key, iv)

        kotlin.test.assertEquals(16, cipher.tagLength)

        val result = cipher.encrypt(packetLengthBytes(16), ByteArray(16))
        kotlin.test.assertEquals(16, result.tag.size)
    }

    @Test
    fun aadMismatchCausesAuthFailure() {
        val key = ByteArray(16) { it.toByte() }
        val iv = makeIv()
        val plaintext = ByteArray(32) { 0xAA.toByte() }
        val packetLength = packetLengthBytes(plaintext.size)

        val encryptor = AesGcmCipher(key, iv)
        val decryptor = AesGcmCipher(key, iv.copyOf())

        val result = encryptor.encrypt(packetLength, plaintext)

        val wrongPacketLength = packetLengthBytes(plaintext.size + 1)
        assertFailsWith<TransportException> {
            decryptor.decrypt(wrongPacketLength, result.ciphertext, result.tag)
        }
    }

    @Test
    fun ciphertextTamperingDetected() {
        val key = ByteArray(16) { it.toByte() }
        val iv = makeIv()
        val plaintext = ByteArray(32) { 0xBB.toByte() }
        val packetLength = packetLengthBytes(plaintext.size)

        val encryptor = AesGcmCipher(key, iv)
        val decryptor = AesGcmCipher(key, iv.copyOf())

        val result = encryptor.encrypt(packetLength, plaintext)

        val tampered = result.ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xFF).toByte()

        assertFailsWith<TransportException> {
            decryptor.decrypt(packetLength, tampered, result.tag)
        }
    }

    @Test
    fun tagTamperingDetected() {
        val key = ByteArray(16) { it.toByte() }
        val iv = makeIv()
        val plaintext = ByteArray(32) { 0xCC.toByte() }
        val packetLength = packetLengthBytes(plaintext.size)

        val encryptor = AesGcmCipher(key, iv)
        val decryptor = AesGcmCipher(key, iv.copyOf())

        val result = encryptor.encrypt(packetLength, plaintext)

        val tamperedTag = result.tag.copyOf()
        tamperedTag[0] = (tamperedTag[0].toInt() xor 0xFF).toByte()

        assertFailsWith<TransportException> {
            decryptor.decrypt(packetLength, result.ciphertext, tamperedTag)
        }
    }

    @Test
    fun ivIncrementsProduceDifferentCiphertext() {
        val key = ByteArray(16) { it.toByte() }
        val iv = makeIv()
        val plaintext = ByteArray(32) { 0xDD.toByte() }
        val packetLength = packetLengthBytes(plaintext.size)

        val cipher = AesGcmCipher(key, iv)

        val result1 = cipher.encrypt(packetLength, plaintext)
        val result2 = cipher.encrypt(packetLength, plaintext)

        // Same plaintext, same AAD, but different nonce → different ciphertext
        kotlin.test.assertFalse(result1.ciphertext.contentEquals(result2.ciphertext))
    }

    @Test
    fun multiplePacketsRoundTrip() {
        val key = ByteArray(32) { it.toByte() }
        val iv = makeIv()

        val encryptor = AesGcmCipher(key, iv)
        val decryptor = AesGcmCipher(key, iv.copyOf())

        for (i in 0 until 5) {
            val plaintext = ByteArray(32) { (it + i).toByte() }
            val packetLength = packetLengthBytes(plaintext.size)

            val result = encryptor.encrypt(packetLength, plaintext)
            val decrypted = decryptor.decrypt(packetLength, result.ciphertext, result.tag)

            assertArrayEquals("Packet $i failed", plaintext, decrypted)
        }
    }

    @Test
    fun rejectsInvalidKeySize() {
        val badKey = ByteArray(24) // neither 16 nor 32
        val iv = makeIv()

        assertFailsWith<IllegalArgumentException> {
            AesGcmCipher(badKey, iv)
        }
    }

    @Test
    fun rejectsInvalidIvSize() {
        val key = ByteArray(16) { it.toByte() }
        val badIv = ByteArray(16) // must be 12

        assertFailsWith<IllegalArgumentException> {
            AesGcmCipher(key, badIv)
        }
    }
}
