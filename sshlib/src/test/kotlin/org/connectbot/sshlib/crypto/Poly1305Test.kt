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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class Poly1305Test {

    private fun hexToBytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // RFC 8439 Section 2.5.2 test vector
    private val rfcKey = hexToBytes(
        "85d6be7857556d337f4452fe42d506a8" +
            "0103808afb0db2fd4abff6af4149f51b",
    )
    private val rfcMessage = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
    private val rfcExpectedTag = hexToBytes("a8061dc1305136c6c22b8baf0c0127a9")

    @Test
    fun `RFC 8439 test vector`() {
        val poly = Poly1305()
        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val tag = ByteArray(16)
        poly.finish(tag, 0)
        assertContentEquals(rfcExpectedTag, tag)
    }

    @Test
    fun `empty message produces correct tag`() {
        // Key of all zeros with empty message
        val key = ByteArray(32)
        val poly = Poly1305()
        poly.init(key)
        val tag = ByteArray(16)
        poly.finish(tag, 0)
        // Empty message with zero key → tag = s = 0
        assertContentEquals(ByteArray(16), tag)
    }

    @Test
    fun `exact block size input`() {
        val poly1 = Poly1305()
        poly1.init(rfcKey)
        val block = ByteArray(16) { it.toByte() }
        poly1.update(block, 0, 16)
        val tag1 = ByteArray(16)
        poly1.finish(tag1, 0)

        // Feed same data as two 8-byte chunks
        val poly2 = Poly1305()
        poly2.init(rfcKey)
        poly2.update(block, 0, 8)
        poly2.update(block, 8, 8)
        val tag2 = ByteArray(16)
        poly2.finish(tag2, 0)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `multiple blocks produce same tag regardless of chunk size`() {
        val data = ByteArray(100) { it.toByte() }

        val poly1 = Poly1305()
        poly1.init(rfcKey)
        poly1.update(data, 0, data.size)
        val tag1 = ByteArray(16)
        poly1.finish(tag1, 0)

        // Feed byte by byte
        val poly2 = Poly1305()
        poly2.init(rfcKey)
        for (i in data.indices) {
            poly2.update(data, i, 1)
        }
        val tag2 = ByteArray(16)
        poly2.finish(tag2, 0)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `finish throws after already finished`() {
        val poly = Poly1305()
        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val tag = ByteArray(16)
        poly.finish(tag, 0)
        assertFailsWith<IllegalStateException> {
            poly.finish(tag, 0)
        }
    }

    @Test
    fun `update throws after finish`() {
        val poly = Poly1305()
        poly.init(rfcKey)
        val tag = ByteArray(16)
        poly.finish(tag, 0)
        assertFailsWith<IllegalStateException> {
            poly.update(rfcMessage, 0, rfcMessage.size)
        }
    }

    @Test
    fun `init resets state for reuse`() {
        val poly = Poly1305()
        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val tag1 = ByteArray(16)
        poly.finish(tag1, 0)

        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val tag2 = ByteArray(16)
        poly.finish(tag2, 0)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `different keys produce different tags`() {
        val key2 = rfcKey.clone().also { it[0] = (it[0].toInt() xor 0xff).toByte() }

        val poly1 = Poly1305()
        poly1.init(rfcKey)
        poly1.update(rfcMessage, 0, rfcMessage.size)
        val tag1 = ByteArray(16)
        poly1.finish(tag1, 0)

        val poly2 = Poly1305()
        poly2.init(key2)
        poly2.update(rfcMessage, 0, rfcMessage.size)
        val tag2 = ByteArray(16)
        poly2.finish(tag2, 0)

        assertFalse(tag1.contentEquals(tag2))
    }

    @Test
    fun `rejects key not 32 bytes`() {
        val poly = Poly1305()
        assertFailsWith<IllegalArgumentException> {
            poly.init(ByteArray(16))
        }
    }

    @Test
    fun `partial last block is handled correctly`() {
        // Message of 17 bytes: one full block + 1 byte remainder
        val data = ByteArray(17) { (it + 1).toByte() }

        val poly1 = Poly1305()
        poly1.init(rfcKey)
        poly1.update(data, 0, data.size)
        val tag1 = ByteArray(16)
        poly1.finish(tag1, 0)

        // Feed as 16 + 1
        val poly2 = Poly1305()
        poly2.init(rfcKey)
        poly2.update(data, 0, 16)
        poly2.update(data, 16, 1)
        val tag2 = ByteArray(16)
        poly2.finish(tag2, 0)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `tag written at correct offset`() {
        val poly = Poly1305()
        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val buffer = ByteArray(20)
        poly.finish(buffer, 4)
        assertContentEquals(rfcExpectedTag, buffer.copyOfRange(4, 20))
        // First 4 bytes untouched
        assertContentEquals(ByteArray(4), buffer.copyOfRange(0, 4))
    }

    @Test
    fun `finish resets accumulator so re-init produces clean state`() {
        // If finish() doesn't call reset(), the accumulator (h0-h4) carries over into the
        // next init(), corrupting the result even with the same key and message.
        val poly = Poly1305()
        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val tag1 = ByteArray(16)
        poly.finish(tag1, 0)

        // Re-init with the same key and same message — must produce the same tag.
        // If h0-h4 weren't zeroed by reset(), the result would differ.
        poly.init(rfcKey)
        poly.update(rfcMessage, 0, rfcMessage.size)
        val tag2 = ByteArray(16)
        poly.finish(tag2, 0)

        assertContentEquals(rfcExpectedTag, tag1)
        assertContentEquals(rfcExpectedTag, tag2)
    }

    // RFC 8439 §A.3 additional test vectors

    @Test
    fun `test vector 2 - all zeros key and message`() {
        val key = ByteArray(32)
        val message = ByteArray(64)
        val expected = ByteArray(16)
        val poly = Poly1305()
        poly.init(key)
        poly.update(message, 0, message.size)
        val tag = ByteArray(16)
        poly.finish(tag, 0)
        assertContentEquals(expected, tag)
    }

    @Test
    fun `test vector 3 - wrap-around with 2^130 - 5`() {
        val key = hexToBytes(
            "0200000000000000000000000000000000000000000000000000000000000000",
        )
        val message = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        val poly = Poly1305()
        poly.init(key)
        poly.update(message, 0, message.size)
        val tag = ByteArray(16)
        poly.finish(tag, 0)
        // Expected: 0x03000000000000000000000000000000
        assertContentEquals(hexToBytes("03000000000000000000000000000000"), tag)
    }
}
