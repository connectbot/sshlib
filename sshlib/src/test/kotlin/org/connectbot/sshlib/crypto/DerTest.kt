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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
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
}
