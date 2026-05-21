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

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class PacketPrimitiveInterfacesTest {

    @Test
    fun `PacketCipher default destroy state is false`() {
        val cipher = object : PacketCipher {
            override val blockSize: Int = 8
            override fun encrypt(data: ByteArray): ByteArray = data
            override fun decrypt(data: ByteArray): ByteArray = data
        }

        cipher.destroy()

        assertFalse(cipher.isDestroyed)
        assertEquals(8, cipher.blockSize)
        assertContentEquals(byteArrayOf(1), cipher.encrypt(byteArrayOf(1)))
        assertContentEquals(byteArrayOf(2), cipher.decrypt(byteArrayOf(2)))
    }

    @Test
    fun `PacketMac default destroy state is false`() {
        val mac = object : PacketMac {
            override val macLength: Int = 4
            override fun compute(sequenceNumber: Long, packet: ByteArray): ByteArray = byteArrayOf(sequenceNumber.toByte())
            override fun computeEtm(sequenceNumber: Long, packetLength: Int, encryptedPayload: ByteArray): ByteArray = byteArrayOf(packetLength.toByte())
        }

        mac.destroy()

        assertFalse(mac.isDestroyed)
        assertEquals(4, mac.macLength)
        assertContentEquals(byteArrayOf(3), mac.compute(3, byteArrayOf()))
        assertContentEquals(byteArrayOf(9), mac.computeEtm(3, 9, byteArrayOf()))
    }

    @Test
    fun `PacketAead defaults do not encrypt length`() {
        val aead = object : PacketAead {
            override val tagLength: Int = 16
            override fun encrypt(packetLength: ByteArray, plaintext: ByteArray): AeadResult = AeadResult(plaintext, packetLength)

            override fun decrypt(packetLength: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray = ciphertext
        }

        aead.destroy()

        assertFalse(aead.isDestroyed)
        assertFalse(aead.encryptsLength)
        assertEquals(16, aead.tagLength)
        assertContentEquals(byteArrayOf(1), aead.encrypt(byteArrayOf(2), byteArrayOf(1)).ciphertext)
        assertContentEquals(byteArrayOf(3), aead.decrypt(byteArrayOf(2), byteArrayOf(3), byteArrayOf(4)))
        assertFailsWith<UnsupportedOperationException> { aead.encryptLength(0, byteArrayOf()) }
        assertFailsWith<UnsupportedOperationException> { aead.decryptLength(0, byteArrayOf()) }
    }
}
