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

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random

class ZlibCompressorTest {

    @Test
    fun roundTrip() {
        val compressor = ZlibCompressor()
        val data = "Hello, SSH compression!".toByteArray()

        val compressed = compressor.compress(data)
        val decompressed = compressor.uncompress(compressed)

        assertArrayEquals(data, decompressed)
    }

    @Test
    fun emptyInput() {
        val compressor = ZlibCompressor()
        val data = ByteArray(0)

        val compressed = compressor.compress(data)
        val decompressed = compressor.uncompress(compressed)

        assertArrayEquals(data, decompressed)
    }

    @Test
    fun largeInput() {
        val compressor = ZlibCompressor()
        val data = Random.nextBytes(128 * 1024)

        val compressed = compressor.compress(data)
        val decompressed = compressor.uncompress(compressed)

        assertArrayEquals(data, decompressed)
    }

    @Test
    fun statefulContextAcrossMultipleCalls() {
        val compressor = ZlibCompressor()
        val decompressor = ZlibCompressor()

        val messages = listOf(
            "first message".toByteArray(),
            "second message".toByteArray(),
            "third message with repeated content: message message message".toByteArray(),
        )

        for (original in messages) {
            val compressed = compressor.compress(original)
            val decompressed = decompressor.uncompress(compressed)
            assertArrayEquals(original, decompressed)
        }
    }

    @Test
    fun repeatedDataCompressesBetter() {
        val compressor = ZlibCompressor()
        val repeatedData = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".repeat(100).toByteArray()

        val compressed = compressor.compress(repeatedData)

        assert(compressed.size < repeatedData.size) {
            "Compressed size (${compressed.size}) should be smaller than original (${repeatedData.size})"
        }
    }

    @Test
    fun compressedOutputIsExactSize() {
        val compressor = ZlibCompressor()
        val decompressor = ZlibCompressor()
        val data = "exact size test data that should roundtrip cleanly".toByteArray()
        val compressed = compressor.compress(data)
        val decompressed = decompressor.uncompress(compressed)
        assertArrayEquals(data, decompressed)
        // Output must be exactly data.size — not zero, not larger
        assertEquals(data.size, decompressed.size)
    }

    @Test
    fun uncompressOutputIsExactSize() {
        val compressor = ZlibCompressor()
        val decompressor = ZlibCompressor()
        // Use data that expands significantly when compressed (already-compressed data grows)
        val data = "abcdefghij".repeat(200).toByteArray()
        val compressed = compressor.compress(data)
        val decompressed = decompressor.uncompress(compressed)
        assertArrayEquals(data, decompressed)
        assertEquals(data.size, decompressed.size)
    }

    @Test
    fun smallInputFitsInInitialBuffer() {
        val compressor = ZlibCompressor()
        val decompressor = ZlibCompressor()
        val data = byteArrayOf(0x42)
        val compressed = compressor.compress(data)
        val decompressed = decompressor.uncompress(compressed)
        assertArrayEquals(data, decompressed)
    }
}
