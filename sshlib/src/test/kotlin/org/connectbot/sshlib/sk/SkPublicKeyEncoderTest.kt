/*
 * Copyright 2026 Kenny Root
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

package org.connectbot.sshlib.sk

import org.connectbot.sshlib.SshException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SkPublicKeyEncoderTest {

    @Test
    fun `encodes sk-ssh-ed25519 blob byte-exact`() {
        val rawKey = ByteArray(32) { i -> (0x40 + i).toByte() }
        val application = "ssh:"

        val blob = SkPublicKeyEncoder.encode(SkAlgorithm.ED25519, rawKey, application)

        // string "sk-ssh-ed25519@openssh.com" || string rawKey(32) || string "ssh:"
        val expected = sshString("sk-ssh-ed25519@openssh.com".toByteArray()) +
            sshString(rawKey) +
            sshString("ssh:".toByteArray())
        assertContentEquals(expected, blob)

        // Spot-check the byte layout explicitly so a future format change is loud.
        // 4-byte length prefix of "sk-ssh-ed25519@openssh.com" = 26 = 0x1a
        assertEquals(0x00.toByte(), blob[0])
        assertEquals(0x00.toByte(), blob[1])
        assertEquals(0x00.toByte(), blob[2])
        assertEquals(0x1a.toByte(), blob[3])
        // Algorithm string starts at offset 4
        assertEquals('s'.code.toByte(), blob[4])
        // After 26-byte algorithm string: 4-byte length = 32 = 0x20
        assertEquals(0x00.toByte(), blob[30])
        assertEquals(0x00.toByte(), blob[31])
        assertEquals(0x00.toByte(), blob[32])
        assertEquals(0x20.toByte(), blob[33])
        // Raw key first byte = 0x40
        assertEquals(0x40.toByte(), blob[34])
    }

    @Test
    fun `encodes sk-ecdsa-sha2-nistp256 blob byte-exact`() {
        val ecPoint = ByteArray(65).also {
            it[0] = 0x04 // uncompressed marker
            for (i in 1..32) it[i] = (0x10 + i).toByte() // X
            for (i in 1..32) it[32 + i] = (0x80 + i).toByte() // Y
        }
        val application = "ssh:"

        val blob = SkPublicKeyEncoder.encode(SkAlgorithm.ECDSA_P256, ecPoint, application)

        val expected = sshString("sk-ecdsa-sha2-nistp256@openssh.com".toByteArray()) +
            sshString("nistp256".toByteArray()) +
            sshString(ecPoint) +
            sshString("ssh:".toByteArray())
        assertContentEquals(expected, blob)
    }

    @Test
    fun `rejects wrong-sized Ed25519 raw key`() {
        assertFailsWith<SshException> {
            SkPublicKeyEncoder.encode(SkAlgorithm.ED25519, ByteArray(31), "ssh:")
        }
        assertFailsWith<SshException> {
            SkPublicKeyEncoder.encode(SkAlgorithm.ED25519, ByteArray(33), "ssh:")
        }
    }

    @Test
    fun `rejects ECDSA point not in uncompressed form`() {
        // Compressed point (starts with 0x02 or 0x03) is rejected
        val compressed = ByteArray(33).also { it[0] = 0x02 }
        assertFailsWith<SshException> {
            SkPublicKeyEncoder.encode(SkAlgorithm.ECDSA_P256, compressed, "ssh:")
        }
        // Wrong-sized uncompressed point is rejected
        val wrongSize = ByteArray(64).also { it[0] = 0x04 }
        assertFailsWith<SshException> {
            SkPublicKeyEncoder.encode(SkAlgorithm.ECDSA_P256, wrongSize, "ssh:")
        }
    }

    @Test
    fun `handles non-ASCII application string`() {
        val rawKey = ByteArray(32)
        val application = "ssh:café"

        val blob = SkPublicKeyEncoder.encode(SkAlgorithm.ED25519, rawKey, application)

        // Application is UTF-8 encoded; round-trip via decoder confirms it survives.
        val decoded = SkPublicKeyDecoder.decode(blob)
        assertEquals(application, decoded.application)
    }

    private fun sshString(bytes: ByteArray): ByteArray {
        val len = bytes.size
        return byteArrayOf(
            (len ushr 24).toByte(),
            (len ushr 16).toByte(),
            (len ushr 8).toByte(),
            len.toByte(),
        ) + bytes
    }
}
