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

import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertFailsWith

class DerTest {

    @Test
    fun testSequenceEncoding() {
        val encoded = encodeDer {
            sequence {
                integer(BigInteger.valueOf(10))
                integer(BigInteger.valueOf(20))
            }
        }

        // Expected:
        // 0x30 (SEQUENCE)
        // 0x06 (Length: 2 + 1 + 1 + 2)
        //   0x02 (INTEGER)
        //   0x01 (Length)
        //   0x0A (10)
        //   0x02 (INTEGER)
        //   0x01 (Length)
        //   0x14 (20)
        val expected = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x0A, 0x02, 0x01, 0x14)

        assertArrayEquals(expected, encoded)
    }

    @Test
    fun testNestedSequence() {
        val encoded = encodeDer {
            sequence {
                sequence {
                    integer(BigInteger.ONE)
                }
            }
        }

        // 30 05 30 03 02 01 01
        val expected = byteArrayOf(0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01)
        assertArrayEquals(expected, encoded)
    }

    @Test
    fun testReader() {
        val data = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x0A, 0x02, 0x01, 0x14)
        val reader = DerReader(data)

        reader.readSequence { seq ->
            val v1 = seq.readInteger()
            val v2 = seq.readInteger()
            assertEquals(BigInteger.valueOf(10), v1)
            assertEquals(BigInteger.valueOf(20), v2)
        }
        reader.ensureFullyConsumed()
    }

    @Test
    fun `rejects trailing bytes after DER data`() {
        val data = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x0A, 0xFF.toByte())
        val reader = DerReader(data)

        reader.readSequence { seq ->
            seq.readInteger()
        }
        assertFailsWith<SshException> {
            reader.ensureFullyConsumed()
        }
    }

    @Test
    fun `rejects unconsumed bytes inside sequence`() {
        // SEQUENCE length says 4 bytes, but only one INTEGER (3 bytes) is read
        val data = byteArrayOf(0x30, 0x04, 0x02, 0x01, 0x0A, 0xFF.toByte())
        val reader = DerReader(data)

        assertFailsWith<SshException> {
            reader.readSequence { seq ->
                seq.readInteger()
            }
        }
    }

    @Test
    fun `readBitString rejects non-zero unused bits`() {
        // BIT STRING with 1 unused bit — not supported
        val data = byteArrayOf(0x03, 0x02, 0x01, 0xFE.toByte())
        val reader = DerReader(data)
        assertFailsWith<SshException> {
            reader.readBitString()
        }
    }

    @Test
    fun `readBitString with zero unused bits succeeds`() {
        // BIT STRING: tag=0x03, length=3, unused=0x00, data=[0xAB, 0xCD]
        val data = byteArrayOf(0x03, 0x03, 0x00, 0xAB.toByte(), 0xCD.toByte())
        val reader = DerReader(data)
        val result = reader.readBitString()
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte()), result)
    }

    @Test
    fun `peekTag returns -1 on empty buffer`() {
        val reader = DerReader(byteArrayOf())
        assertEquals(-1, reader.peekTag())
    }

    @Test
    fun `peekTag returns correct tag without consuming`() {
        val data = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
        val reader = DerReader(data)
        assertEquals(0x30, reader.peekTag())
        assertEquals(0x30, reader.peekTag()) // still the same after peeking
    }

    @Test
    fun `readContextTag succeeds with matching tag`() {
        // Context tag [0]: 0xA0, length=3, INTEGER(1)
        val data = byteArrayOf(0xA0.toByte(), 0x03, 0x02, 0x01, 0x01)
        val reader = DerReader(data)
        val result = reader.readContextTag(0) { inner ->
            inner.readInteger()
        }
        assertEquals(BigInteger.ONE, result)
    }

    @Test
    fun `readContextTag rejects wrong tag`() {
        // Context tag [1] but we ask for [0]
        val data = byteArrayOf(0xA1.toByte(), 0x03, 0x02, 0x01, 0x01)
        val reader = DerReader(data)
        assertFailsWith<SshException> {
            reader.readContextTag(0) { inner -> inner.readInteger() }
        }
    }

    @Test
    fun `readContextTag rejects unconsumed content`() {
        // Context tag [0] with two integers but we only read one
        val data = byteArrayOf(0xA0.toByte(), 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)
        val reader = DerReader(data)
        assertFailsWith<SshException> {
            reader.readContextTag(0) { inner -> inner.readInteger() }
        }
    }

    @Test
    fun `readSequence length subtraction - reads exact bytes`() {
        // Sequence containing exactly 1 integer to verify length arithmetic
        val data = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x7F)
        val reader = DerReader(data)
        reader.readSequence { seq ->
            assertEquals(BigInteger.valueOf(127), seq.readInteger())
        }
        reader.ensureFullyConsumed()
    }
}
