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

import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KeyDecryptionTest {

    // --- hexToByteArray ---

    @Test
    fun `hexToByteArray decodes simple hex string`() {
        val result = KeyDecryption.hexToByteArray("deadbeef")
        assertContentEquals(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()), result)
    }

    @Test
    fun `hexToByteArray decodes all-zeros`() {
        val result = KeyDecryption.hexToByteArray("0000")
        assertContentEquals(byteArrayOf(0, 0), result)
    }

    @Test
    fun `hexToByteArray decodes all-Fs`() {
        val result = KeyDecryption.hexToByteArray("ffff")
        assertContentEquals(byteArrayOf(0xFF.toByte(), 0xFF.toByte()), result)
    }

    @Test
    fun `hexToByteArray works with uppercase`() {
        val result = KeyDecryption.hexToByteArray("DEADBEEF")
        assertContentEquals(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()), result)
    }

    @Test
    fun `hexToByteArray produces correct byte count`() {
        assertEquals(8, KeyDecryption.hexToByteArray("0102030405060708").size)
    }

    @Test
    fun `hexToByteArray rejects odd-length string`() {
        assertFailsWith<IllegalArgumentException> {
            KeyDecryption.hexToByteArray("abc")
        }
    }

    @Test
    fun `hexToByteArray each nibble position is independent`() {
        // High nibble vs low nibble must be separate: "10" = 0x10, not 0x01
        val high = KeyDecryption.hexToByteArray("10")
        val low = KeyDecryption.hexToByteArray("01")
        assertEquals(0x10.toByte(), high[0])
        assertEquals(0x01.toByte(), low[0])
    }

    // --- generateKeyFromPasswordSaltWithMD5 ---

    @Test
    fun `generateKeyFromPasswordSaltWithMD5 produces deterministic output`() {
        val password = "secret".toByteArray()
        val salt = ByteArray(8) { it.toByte() }
        val key1 = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, salt, 16)
        val key2 = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, salt, 16)
        assertContentEquals(key1, key2)
    }

    @Test
    fun `generateKeyFromPasswordSaltWithMD5 returns requested length`() {
        val password = "pass".toByteArray()
        val salt = ByteArray(8)
        for (keyLen in listOf(8, 16, 24, 32)) {
            val key = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, salt, keyLen)
            assertEquals(keyLen, key.size)
        }
    }

    @Test
    fun `generateKeyFromPasswordSaltWithMD5 output differs with different passwords`() {
        val salt = ByteArray(8) { it.toByte() }
        val key1 = KeyDecryption.generateKeyFromPasswordSaltWithMD5("pass1".toByteArray(), salt, 16)
        val key2 = KeyDecryption.generateKeyFromPasswordSaltWithMD5("pass2".toByteArray(), salt, 16)
        assert(!key1.contentEquals(key2)) { "Different passwords must produce different keys" }
    }

    @Test
    fun `generateKeyFromPasswordSaltWithMD5 output differs with different salts`() {
        val password = "pass".toByteArray()
        val key1 = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, ByteArray(8) { 1 }, 16)
        val key2 = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, ByteArray(8) { 2 }, 16)
        assert(!key1.contentEquals(key2)) { "Different salts must produce different keys" }
    }

    @Test
    fun `generateKeyFromPasswordSaltWithMD5 uses only first 8 bytes of long salt`() {
        val password = "pass".toByteArray()
        val salt8 = ByteArray(8) { 0xAA.toByte() }
        val salt16 = ByteArray(16) { 0xAA.toByte() }
        val key8 = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, salt8, 16)
        val key16 = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, salt16, 16)
        assertContentEquals(key8, key16)
    }

    // --- decryptPem (via removePkcs7Padding) ---

    @Test
    fun `decryptPem rejects unsupported cipher`() {
        assertFailsWith<SshException> {
            KeyDecryption.decryptPem(ByteArray(16), ByteArray(8), ByteArray(16), "UNSUPPORTED-CIPHER")
        }
    }

    @Test
    fun `decryptPem AES-128 roundtrip`() {
        val password = "testpassword".toByteArray()
        val salt = ByteArray(16) { it.toByte() }
        val plaintext = "Hello, PEM key!".toByteArray(Charsets.ISO_8859_1)

        val encrypted = KeyEncryption.encryptPem(plaintext, password, salt, "AES-128-CBC")
        val decrypted = KeyDecryption.decryptPem(encrypted, password, salt, "AES-128-CBC")

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `decryptPem AES-256 roundtrip`() {
        val password = "testpassword".toByteArray()
        val salt = ByteArray(16) { (it * 3).toByte() }
        val plaintext = "secret data for pem".toByteArray(Charsets.ISO_8859_1)

        val encrypted = KeyEncryption.encryptPem(plaintext, password, salt, "AES-256-CBC")
        val decrypted = KeyDecryption.decryptPem(encrypted, password, salt, "AES-256-CBC")

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `decryptPem throws on wrong password due to bad padding`() {
        val salt = ByteArray(16) { it.toByte() }
        val plaintext = "some data here!".toByteArray(Charsets.ISO_8859_1)

        val encrypted = KeyEncryption.encryptPem(plaintext, "correct".toByteArray(), salt, "AES-256-CBC")
        assertFailsWith<SshException> {
            KeyDecryption.decryptPem(encrypted, "wrong".toByteArray(), salt, "AES-256-CBC")
        }
    }
}
