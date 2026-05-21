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

package org.connectbot.sshlib.protocol

import io.kaitai.struct.KaitaiStream
import io.kaitai.struct.KaitaiStruct
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KaitaiUtilsTest {

    @Test
    fun `toByteArray serializes generated Kaitai struct`() {
        val message = ByteString().apply {
            setLenData(3)
            setData(byteArrayOf(1, 2, 3))
        }

        assertContentEquals(byteArrayOf(0, 0, 0, 3, 1, 2, 3), message.toByteArray())
    }

    @Test
    fun `toByteArray grows buffer when initial capacity is too small`() {
        val payloadSize = 20 * 1024
        val message = FixedPayloadStruct(payloadSize)

        val bytes = message.toByteArray()

        assertEquals(payloadSize, bytes.size)
        assertEquals(0, bytes.first())
        assertEquals((payloadSize - 1).toByte(), bytes.last())
    }

    @Test
    fun `toByteArray fails when message exceeds maximum serialization buffer`() {
        val message = FixedPayloadStruct(1024 * 1024 + 1)

        val exception = assertFailsWith<IllegalStateException> {
            message.toByteArray()
        }
        assertEquals("Kaitai message exceeds 1048576 byte serialization limit", exception.message)
    }

    private class FixedPayloadStruct(
        private val payloadSize: Int,
    ) : KaitaiStruct.ReadWrite(null) {
        override fun _write_Seq() {
            _io.writeBytes(ByteArray(payloadSize) { it.toByte() })
        }

        override fun _check() {
            _dirty = false
        }

        override fun _fetchInstances() = Unit

        override fun _read() = Unit
    }
}
