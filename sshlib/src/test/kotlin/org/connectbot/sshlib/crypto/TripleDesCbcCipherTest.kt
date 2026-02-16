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

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class TripleDesCbcCipherTest {

    @Test
    fun roundTrip() {
        val key = ByteArray(24) { it.toByte() }
        val iv = ByteArray(8) { (it + 1).toByte() }
        val plaintext = ByteArray(16) { (it + 0x41).toByte() } // 2 blocks

        val encryptor = TripleDesCbcCipher(key, iv, forEncryption = true)
        val decryptor = TripleDesCbcCipher(key, iv.copyOf(), forEncryption = false)

        val ciphertext = encryptor.encrypt(plaintext)
        val decrypted = decryptor.decrypt(ciphertext)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun chainingMaintained() {
        val key = ByteArray(24) { it.toByte() }
        val iv = ByteArray(8) { (it + 1).toByte() }

        val encryptor = TripleDesCbcCipher(key, iv, forEncryption = true)

        val plaintext1 = ByteArray(8) { 0xAA.toByte() }
        val plaintext2 = ByteArray(8) { 0xAA.toByte() } // Same plaintext

        val cipher1 = encryptor.encrypt(plaintext1)
        val cipher2 = encryptor.encrypt(plaintext2)

        // In CBC mode, second block encryption depends on first block ciphertext
        assertFalse(cipher1.contentEquals(cipher2))
    }

    @Test
    fun multiplePacketsRoundTrip() {
        val key = ByteArray(24) { it.toByte() }
        val iv = ByteArray(8) { (it + 1).toByte() }

        val encryptor = TripleDesCbcCipher(key, iv, forEncryption = true)
        val decryptor = TripleDesCbcCipher(key, iv.copyOf(), forEncryption = false)

        for (i in 0 until 5) {
            val plaintext = ByteArray(24) { (it + i).toByte() } // 3 blocks

            val ciphertext = encryptor.encrypt(plaintext)
            val decrypted = decryptor.decrypt(ciphertext)

            assertArrayEquals(plaintext, decrypted, "Packet $i failed")
        }
    }

    @Test
    fun rejectsInvalidKeySize() {
        val badKey = ByteArray(16) // too short
        val iv = ByteArray(8)

        assertFailsWith<IllegalArgumentException> {
            TripleDesCbcCipher(badKey, iv, true)
        }
    }

    @Test
    fun rejectsInvalidIvSize() {
        val key = ByteArray(24)
        val badIv = ByteArray(16) // too long

        assertFailsWith<IllegalArgumentException> {
            TripleDesCbcCipher(key, badIv, true)
        }
    }
}
