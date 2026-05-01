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

package org.connectbot.sshlib.protocol

import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.nio.ByteBuffer
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SshBufUtilsTest {

    // --- readString ---

    @Test
    fun `readString reads ASCII content`() {
        val data = "hello".toByteArray(Charsets.US_ASCII)
        val buf = ByteBuffer.allocate(4 + data.size)
        buf.putInt(data.size)
        buf.put(data)
        buf.rewind()
        assertEquals("hello", buf.readString())
    }

    @Test
    fun `readString throws on negative length`() {
        val buf = ByteBuffer.allocate(4)
        buf.putInt(-1)
        buf.rewind()
        assertFailsWith<IllegalArgumentException> {
            buf.readString()
        }
    }

    @Test
    fun `readString throws when length exceeds remaining`() {
        val buf = ByteBuffer.allocate(4)
        buf.putInt(100)
        buf.rewind()
        assertFailsWith<IllegalArgumentException> {
            buf.readString()
        }
    }

    // --- readByteString ---

    @Test
    fun `readByteString reads byte array`() {
        val data = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val buf = ByteBuffer.allocate(4 + data.size)
        buf.putInt(data.size)
        buf.put(data)
        buf.rewind()
        assertContentEquals(data, buf.readByteString())
    }

    @Test
    fun `readByteString throws on length exceeding remaining`() {
        val buf = ByteBuffer.allocate(4)
        buf.putInt(50)
        buf.rewind()
        assertFailsWith<IllegalArgumentException> {
            buf.readByteString()
        }
    }

    // --- readMpint ---

    @Test
    fun `readMpint empty bytes returns zero`() {
        val buf = ByteBuffer.allocate(4)
        buf.putInt(0)
        buf.rewind()
        assertEquals(BigInteger.ZERO, buf.readMpint())
    }

    @Test
    fun `readMpint positive value`() {
        val bytes = byteArrayOf(0x01, 0x00)
        val buf = ByteBuffer.allocate(4 + bytes.size)
        buf.putInt(bytes.size)
        buf.put(bytes)
        buf.rewind()
        assertEquals(BigInteger("256"), buf.readMpint())
    }

    // --- createMpint ---

    @Test
    fun `createMpint positive value with high bit set gets zero prefix`() {
        val mpint = createMpint(byteArrayOf(0xFF.toByte()))
        assertEquals(2, mpint.body().size)
        assertEquals(0.toByte(), mpint.body()[0])
        assertEquals(0xFF.toByte(), mpint.body()[1])
    }

    @Test
    fun `createMpint positive value without high bit needs no prefix`() {
        val mpint = createMpint(byteArrayOf(0x7F))
        assertEquals(1, mpint.body().size)
        assertEquals(0x7F.toByte(), mpint.body()[0])
    }

    @Test
    fun `createMpint strips leading zeros`() {
        // [0, 0, 0x01] → body is [0x01]
        val mpint = createMpint(byteArrayOf(0, 0, 0x01))
        assertEquals(1, mpint.body().size)
        assertEquals(0x01.toByte(), mpint.body()[0])
    }

    @Test
    fun `createMpint does not strip the sole non-zero byte before high-bit value`() {
        // [0, 0xFF] → the 0xFF has high bit set, so body is [0x00, 0xFF]
        val mpint = createMpint(byteArrayOf(0, 0xFF.toByte()))
        assertEquals(2, mpint.body().size)
        assertEquals(0.toByte(), mpint.body()[0])
        assertEquals(0xFF.toByte(), mpint.body()[1])
    }

    @Test
    fun `createMpint body length matches lenBody field`() {
        val mpint = createMpint(byteArrayOf(0x01, 0x02, 0x03))
        assertEquals(mpint.body().size.toLong(), mpint.lenBody())
    }

    @Test
    fun `createMpint from BigInteger value 256`() {
        val mpint = createMpint(BigInteger.valueOf(256))
        // 256 = 0x0100 — no high bit, so body = [0x01, 0x00]
        assertEquals(2, mpint.body().size)
        assertEquals(0x01.toByte(), mpint.body()[0])
        assertEquals(0x00.toByte(), mpint.body()[1])
    }

    @Test
    fun `createMpint from BigInteger 128 has zero prefix`() {
        // 128 = 0x80, high bit set → needs zero prefix: body = [0x00, 0x80]
        val mpint = createMpint(BigInteger.valueOf(128))
        assertEquals(2, mpint.body().size)
        assertEquals(0x00.toByte(), mpint.body()[0])
        assertEquals(0x80.toByte(), mpint.body()[1])
    }

    @Test
    fun `createMpint single non-zero byte without high bit`() {
        val mpint = createMpint(byteArrayOf(0x01))
        assertEquals(1, mpint.body().size)
        assertEquals(0x01.toByte(), mpint.body()[0])
    }

    // --- createNameList ---

    @Test
    fun `createNameList empty string`() {
        val nl = createNameList("")
        assertEquals(0L, nl.lenEntries())
    }

    @Test
    fun `createNameList single entry`() {
        val nl = createNameList("ssh-rsa")
        val data = nl.entries().data()
        assertEquals(1, data.size)
        assertEquals("ssh-rsa", data[0])
    }

    @Test
    fun `createNameList multiple entries`() {
        val nl = createNameList("ssh-rsa,ssh-ed25519")
        val data = nl.entries().data()
        assertEquals(2, data.size)
        assertEquals("ssh-rsa", data[0])
        assertEquals("ssh-ed25519", data[1])
    }

    @Test
    fun `createNameList lenEntries is byte length not entry count`() {
        val name = "ssh-rsa"
        val nl = createNameList(name)
        assertEquals(name.toByteArray(Charsets.US_ASCII).size.toLong(), nl.lenEntries())
    }
}
