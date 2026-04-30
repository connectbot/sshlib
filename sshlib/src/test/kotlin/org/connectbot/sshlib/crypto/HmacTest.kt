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

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class HmacTest {

    // --- HmacSha1 ---

    @Test
    fun `HmacSha1 compute is deterministic across multiple calls`() {
        val key = ByteArray(20) { it.toByte() }
        val mac = HmacSha1(key)
        val packet = byteArrayOf(1, 2, 3, 4, 5)

        val tag1 = mac.compute(0, packet)
        val tag2 = mac.compute(0, packet)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `HmacSha1 compute reset works - different seqnums produce different tags`() {
        val key = ByteArray(20) { it.toByte() }
        val mac = HmacSha1(key)
        val packet = byteArrayOf(1, 2, 3)

        val tag0 = mac.compute(0, packet)
        val tag1 = mac.compute(1, packet)

        assertFalse(tag0.contentEquals(tag1), "Different sequence numbers must produce different tags")
    }

    @Test
    fun `HmacSha1 sequential calls produce same result as fresh instance`() {
        // If mac.reset() is removed, state from the previous call leaks into the next one,
        // so the same (seqnum, packet) pair would produce a different tag on the second call.
        val key = ByteArray(20) { it.toByte() }
        val mac = HmacSha1(key)
        val packet = byteArrayOf(0xAA.toByte(), 0xBB.toByte())

        val first = mac.compute(3L, packet)
        // Second call must equal a fresh instance computing the same inputs
        val fresh = HmacSha1(key)
        val expected = fresh.compute(3L, packet)
        assertContentEquals(expected, first)

        // And calling again on the reused instance must still match
        val second = mac.compute(3L, packet)
        assertContentEquals(expected, second)
    }

    @Test
    fun `HmacSha1 computeEtm is deterministic`() {
        val key = ByteArray(20) { it.toByte() }
        val mac = HmacSha1(key)
        val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)

        val tag1 = mac.computeEtm(42, 8, payload)
        val tag2 = mac.computeEtm(42, 8, payload)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `HmacSha1 computeEtm reset works across calls`() {
        val key = ByteArray(20) { it.toByte() }
        val mac = HmacSha1(key)
        val payload = byteArrayOf(1, 2, 3, 4)

        val tag0 = mac.computeEtm(0, 4, payload)
        val tag1 = mac.computeEtm(1, 4, payload)

        assertFalse(tag0.contentEquals(tag1))
    }

    @Test
    fun `HmacSha1 rejects wrong key size`() {
        assertFailsWith<IllegalArgumentException> {
            HmacSha1(ByteArray(32))
        }
    }

    @Test
    fun `HmacSha1 macLength is 20`() {
        assertEquals(20, HmacSha1(ByteArray(20)).macLength)
    }

    // --- HmacSha256 ---

    @Test
    fun `HmacSha256 compute is deterministic across multiple calls`() {
        val key = ByteArray(32) { it.toByte() }
        val mac = HmacSha256(key)
        val packet = byteArrayOf(1, 2, 3, 4, 5)

        val tag1 = mac.compute(0, packet)
        val tag2 = mac.compute(0, packet)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `HmacSha256 compute reset works - different seqnums produce different tags`() {
        val key = ByteArray(32) { it.toByte() }
        val mac = HmacSha256(key)
        val packet = byteArrayOf(1, 2, 3)

        val tag0 = mac.compute(0, packet)
        val tag1 = mac.compute(1, packet)

        assertFalse(tag0.contentEquals(tag1))
    }

    @Test
    fun `HmacSha256 computeEtm is deterministic`() {
        val key = ByteArray(32) { it.toByte() }
        val mac = HmacSha256(key)
        val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)

        val tag1 = mac.computeEtm(42, 8, payload)
        val tag2 = mac.computeEtm(42, 8, payload)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `HmacSha256 computeEtm reset works across calls`() {
        val key = ByteArray(32) { it.toByte() }
        val mac = HmacSha256(key)
        val payload = byteArrayOf(1, 2, 3, 4)

        val tag0 = mac.computeEtm(0, 4, payload)
        val tag1 = mac.computeEtm(1, 4, payload)

        assertFalse(tag0.contentEquals(tag1))
    }

    @Test
    fun `HmacSha256 rejects wrong key size`() {
        assertFailsWith<IllegalArgumentException> {
            HmacSha256(ByteArray(20))
        }
    }

    @Test
    fun `HmacSha256 macLength is 32`() {
        assertEquals(32, HmacSha256(ByteArray(32)).macLength)
    }

    @Test
    fun `HmacSha256 destroy zeroes key`() {
        val key = ByteArray(32) { it.toByte() }
        val mac = HmacSha256(key)
        mac.destroy()
        assertContentEquals(ByteArray(32), key)
    }

    // --- HmacSha512 ---

    @Test
    fun `HmacSha512 compute is deterministic across multiple calls`() {
        val key = ByteArray(64) { it.toByte() }
        val mac = HmacSha512(key)
        val packet = byteArrayOf(1, 2, 3, 4, 5)

        val tag1 = mac.compute(0, packet)
        val tag2 = mac.compute(0, packet)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `HmacSha512 compute reset works - different seqnums produce different tags`() {
        val key = ByteArray(64) { it.toByte() }
        val mac = HmacSha512(key)
        val packet = byteArrayOf(1, 2, 3)

        val tag0 = mac.compute(0, packet)
        val tag1 = mac.compute(1, packet)

        assertFalse(tag0.contentEquals(tag1))
    }

    @Test
    fun `HmacSha512 computeEtm is deterministic`() {
        val key = ByteArray(64) { it.toByte() }
        val mac = HmacSha512(key)
        val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)

        val tag1 = mac.computeEtm(42, 8, payload)
        val tag2 = mac.computeEtm(42, 8, payload)

        assertContentEquals(tag1, tag2)
    }

    @Test
    fun `HmacSha512 computeEtm reset works across calls`() {
        val key = ByteArray(64) { it.toByte() }
        val mac = HmacSha512(key)
        val payload = byteArrayOf(1, 2, 3, 4)

        val tag0 = mac.computeEtm(0, 4, payload)
        val tag1 = mac.computeEtm(1, 4, payload)

        assertFalse(tag0.contentEquals(tag1))
    }

    @Test
    fun `HmacSha512 macLength is 64`() {
        assertEquals(64, HmacSha512(ByteArray(64)).macLength)
    }
}
