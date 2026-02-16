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

class AesCbcCipherTest {

    @Test
    fun roundTripAes128() {
        val key = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it + 1).toByte() }
        val plaintext = ByteArray(32) { (it + 0x41).toByte() }

        val encryptor = AesCbcCipher(key, iv, forEncryption = true)
        val decryptor = AesCbcCipher(key, iv.copyOf(), forEncryption = false)

        val ciphertext = encryptor.encrypt(plaintext)
        val decrypted = decryptor.decrypt(ciphertext)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun roundTripAes256() {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(16) { (it + 1).toByte() }
        val plaintext = ByteArray(48) { (it + 0x30).toByte() }

        val encryptor = AesCbcCipher(key, iv, forEncryption = true)
        val decryptor = AesCbcCipher(key, iv.copyOf(), forEncryption = false)

        val ciphertext = encryptor.encrypt(plaintext)
        val decrypted = decryptor.decrypt(ciphertext)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun chainingMaintained() {
        val key = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it + 1).toByte() }

        val encryptor = AesCbcCipher(key, iv, forEncryption = true)

        val plaintext1 = ByteArray(16) { 0xAA.toByte() }
        val plaintext2 = ByteArray(16) { 0xAA.toByte() }

        val cipher1 = encryptor.encrypt(plaintext1)
        val cipher2 = encryptor.encrypt(plaintext2)

        assertFalse(cipher1.contentEquals(cipher2))
    }

    @Test
    fun rejectsInvalidKeySize() {
        val badKey = ByteArray(24) // not 16 or 32
        val iv = ByteArray(16)

        assertFailsWith<IllegalArgumentException> {
            AesCbcCipher(badKey, iv, true)
        }
    }

    @Test
    fun rejectsInvalidIvSize() {
        val key = ByteArray(16)
        val badIv = ByteArray(12)

        assertFailsWith<IllegalArgumentException> {
            AesCbcCipher(key, badIv, true)
        }
    }
}
