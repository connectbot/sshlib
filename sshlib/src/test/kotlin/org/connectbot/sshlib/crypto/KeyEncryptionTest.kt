/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

class KeyEncryptionTest {

    @Test
    fun `encryptPem supports DES and AES key sizes`() {
        val password = "secret".toByteArray()
        val plaintext = "PEM payload".toByteArray(Charsets.ISO_8859_1)

        for (cipherName in listOf("DES-CBC", "DES-EDE3-CBC")) {
            val salt = ByteArray(8) { (it + 1).toByte() }
            val encrypted = KeyEncryption.encryptPem(plaintext, password, salt, cipherName)
            assertContentEquals(plaintext, KeyDecryption.decryptPem(encrypted, password, salt, cipherName))
        }

        for (cipherName in listOf("AES-192-CBC")) {
            val salt = ByteArray(16) { (it + 1).toByte() }
            val encrypted = KeyEncryption.encryptPem(plaintext, password, salt, cipherName)
            assertContentEquals(plaintext, KeyDecryption.decryptPem(encrypted, password, salt, cipherName))
        }
    }

    @Test
    fun `encryptPem rejects unsupported cipher`() {
        assertFailsWith<SshException> {
            KeyEncryption.encryptPem(byteArrayOf(1), byteArrayOf(2), ByteArray(16), "AES-512-CBC")
        }
    }

    @Test
    fun `encryptOpenSsh roundtrips supported ciphers`() {
        val password = "secret".toByteArray()
        val salt = ByteArray(16) { (it * 3).toByte() }
        val plaintext = ByteArray(32) { it.toByte() }

        for (cipherName in listOf("aes256-ctr", "aes256-cbc", "aes128-ctr", "aes128-cbc")) {
            val encrypted = KeyEncryption.encryptOpenSsh(plaintext, password, salt, 8, cipherName)
            assertContentEquals(plaintext, KeyDecryption.decryptOpenSsh(encrypted, password, salt, 8, cipherName))
        }
    }

    @Test
    fun `encryptOpenSsh rejects unsupported cipher`() {
        assertFailsWith<SshException> {
            KeyEncryption.encryptOpenSsh(byteArrayOf(1), byteArrayOf(2), ByteArray(16), 4, "aes192-ctr")
        }
    }

    @Test
    fun `addPkcs7Padding adds a full block when already aligned`() {
        val padded = KeyEncryption.addPkcs7Padding(byteArrayOf(1, 2, 3, 4), 4)

        assertContentEquals(byteArrayOf(1, 2, 3, 4, 4, 4, 4, 4), padded)
    }

    @Test
    fun `byteArrayToHex uses uppercase two character bytes`() {
        assertEquals("000FA5FF", KeyEncryption.byteArrayToHex(byteArrayOf(0x00, 0x0F, 0xA5.toByte(), 0xFF.toByte())))
    }
}
