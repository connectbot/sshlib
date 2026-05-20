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

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class SshEncodingTest {

    // --- encodeMpint ---

    @Test
    fun `encodeMpint zero encodes as length 0 per RFC 4251`() {
        val result = encodeMpint(byteArrayOf(0))
        assertContentEquals(byteArrayOf(0, 0, 0, 0), result)
    }

    @Test
    fun `encodeMpint all-zeros input encodes as length 0`() {
        val result = encodeMpint(byteArrayOf(0, 0, 0))
        assertContentEquals(byteArrayOf(0, 0, 0, 0), result)
    }

    @Test
    fun `encodeMpint strips leading zeros`() {
        // [0x00, 0x01] should encode as mpint(1) = 4-byte length 1 + byte 0x01
        val result = encodeMpint(byteArrayOf(0x00, 0x01))
        assertContentEquals(byteArrayOf(0, 0, 0, 1, 0x01), result)
    }

    @Test
    fun `encodeMpint pads when high bit set`() {
        // 0x80 has high bit set → needs 0x00 prefix
        val result = encodeMpint(byteArrayOf(0x80.toByte()))
        assertContentEquals(byteArrayOf(0, 0, 0, 2, 0x00, 0x80.toByte()), result)
    }

    @Test
    fun `encodeMpint does not pad when high bit clear`() {
        val result = encodeMpint(byteArrayOf(0x7f))
        assertContentEquals(byteArrayOf(0, 0, 0, 1, 0x7f), result)
    }

    @Test
    fun `encodeMpint encodes length correctly for multi-byte values`() {
        val value = ByteArray(16) { (it + 1).toByte() }
        val result = encodeMpint(value)
        assertEquals(4 + 16, result.size)
        assertEquals(
            16,
            ((result[0].toInt() and 0xff) shl 24) or
                ((result[1].toInt() and 0xff) shl 16) or
                ((result[2].toInt() and 0xff) shl 8) or
                (result[3].toInt() and 0xff),
        )
    }

    @Test
    fun `encodeMpint strips multiple leading zeros but keeps one non-zero byte`() {
        val result = encodeMpint(byteArrayOf(0, 0, 0, 0x42))
        assertContentEquals(byteArrayOf(0, 0, 0, 1, 0x42), result)
    }

    @Test
    fun `encodeMpint preserves value without leading zeros`() {
        val value = byteArrayOf(0x01, 0x02, 0x03)
        val result = encodeMpint(value)
        assertContentEquals(byteArrayOf(0, 0, 0, 3, 0x01, 0x02, 0x03), result)
    }

    // --- encodeSshString ---

    @Test
    fun `encodeSshString empty input produces 4-byte zero length`() {
        val result = encodeSshString(ByteArray(0))
        assertContentEquals(byteArrayOf(0, 0, 0, 0), result)
    }

    @Test
    fun `encodeSshString encodes length in big-endian`() {
        val data = ByteArray(256) { it.toByte() }
        val result = encodeSshString(data)
        assertEquals(4 + 256, result.size)
        // Length bytes: 0x00, 0x00, 0x01, 0x00
        assertContentEquals(byteArrayOf(0, 0, 1, 0), result.copyOfRange(0, 4))
        assertContentEquals(data, result.copyOfRange(4, result.size))
    }

    @Test
    fun `encodeSshString encodes high byte of length`() {
        val data = ByteArray(0x01_00_00) { 0 }
        val result = encodeSshString(data)
        // Length = 65536 = 0x00_01_00_00
        assertContentEquals(byteArrayOf(0, 1, 0, 0), result.copyOfRange(0, 4))
    }

    @Test
    fun `encodeSshString roundtrip via shift operations`() {
        val payload = "hello".toByteArray(Charsets.UTF_8)
        val result = encodeSshString(payload)
        val length = ((result[0].toInt() and 0xff) shl 24) or
            ((result[1].toInt() and 0xff) shl 16) or
            ((result[2].toInt() and 0xff) shl 8) or
            (result[3].toInt() and 0xff)
        assertEquals(payload.size, length)
        assertContentEquals(payload, result.copyOfRange(4, result.size))
    }
}
