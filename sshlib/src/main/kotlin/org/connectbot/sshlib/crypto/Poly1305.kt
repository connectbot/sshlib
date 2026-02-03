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

/**
 * Poly1305 one-time authenticator per RFC 8439.
 *
 * Uses a 5x27-bit limb accumulator representation for the modular arithmetic.
 */
class Poly1305 {
    companion object {
        private const val BLOCK_SIZE = 16
    }

    private var h0 = 0; private var h1 = 0; private var h2 = 0; private var h3 = 0; private var h4 = 0
    private var r0 = 0; private var r1 = 0; private var r2 = 0; private var r3 = 0; private var r4 = 0
    private var s0 = 0; private var s1 = 0; private var s2 = 0; private var s3 = 0

    private var buffer = ByteArray(BLOCK_SIZE)
    private var bufferPos = 0
    private var finished = false

    fun init(key: ByteArray) {
        require(key.size == 32) { "Poly1305 key must be 32 bytes" }

        val t0 = readIntLE(key, 0)
        val t1 = readIntLE(key, 4)
        val t2 = readIntLE(key, 8)
        val t3 = readIntLE(key, 12)

        r0 = t0 and 0x3ffffff
        r1 = ((t0 ushr 26) or (t1 shl 6)) and 0x3ffff03
        r2 = ((t1 ushr 20) or (t2 shl 12)) and 0x3ffc0ff
        r3 = ((t2 ushr 14) or (t3 shl 18)) and 0x3f03fff
        r4 = (t3 ushr 8) and 0x00fffff

        s0 = readIntLE(key, 16)
        s1 = readIntLE(key, 20)
        s2 = readIntLE(key, 24)
        s3 = readIntLE(key, 28)

        h0 = 0; h1 = 0; h2 = 0; h3 = 0; h4 = 0
        buffer = ByteArray(BLOCK_SIZE)
        bufferPos = 0
        finished = false
    }

    fun update(data: ByteArray, offset: Int, length: Int) {
        check(!finished) { "Poly1305 already finished" }

        var remaining = length
        var pos = offset

        if (bufferPos > 0) {
            val toCopy = minOf(BLOCK_SIZE - bufferPos, remaining)
            System.arraycopy(data, pos, buffer, bufferPos, toCopy)
            bufferPos += toCopy
            pos += toCopy
            remaining -= toCopy

            if (bufferPos == BLOCK_SIZE) {
                processBlock(buffer, 0, false)
                bufferPos = 0
            }
        }

        while (remaining >= BLOCK_SIZE) {
            processBlock(data, pos, false)
            pos += BLOCK_SIZE
            remaining -= BLOCK_SIZE
        }

        if (remaining > 0) {
            System.arraycopy(data, pos, buffer, 0, remaining)
            bufferPos = remaining
        }
    }

    fun finish(tag: ByteArray, offset: Int) {
        check(!finished) { "Poly1305 already finished" }

        if (bufferPos > 0) {
            buffer[bufferPos] = 1
            for (i in bufferPos + 1 until BLOCK_SIZE) {
                buffer[i] = 0
            }
            bufferPos++
            processBlock(buffer, 0, true)
        }

        // Fully reduce h mod (2^130 - 5)
        var c: Long

        c = Integer.toUnsignedLong(h0) + 5
        val g0 = c.toInt() and 0x03ffffff
        c = c ushr 26
        c += h1
        val g1 = c.toInt() and 0x03ffffff
        c = c ushr 26
        c += h2
        val g2 = c.toInt() and 0x03ffffff
        c = c ushr 26
        c += h3
        val g3 = c.toInt() and 0x03ffffff
        c = c ushr 26
        c += h4
        var g4 = c.toInt() and 0x03ffffff
        g4 -= (1 shl 26)

        var mask = -(c ushr 26).toInt()
        val nmask = mask.inv()
        h0 = (h0 and nmask) or (g0 and mask)
        h1 = (h1 and nmask) or (g1 and mask)
        h2 = (h2 and nmask) or (g2 and mask)
        h3 = (h3 and nmask) or (g3 and mask)
        h4 = (h4 and nmask) or (g4 and mask)

        // h = h mod 2^128
        h0 = h0 or (h1 shl 26)
        h1 = (h1 ushr 6) or (h2 shl 20)
        h2 = (h2 ushr 12) or (h3 shl 14)
        h3 = (h3 ushr 18) or (h4 shl 8)

        // h = (h + s) mod 2^128
        c = Integer.toUnsignedLong(h0) + Integer.toUnsignedLong(s0)
        h0 = c.toInt()
        c = Integer.toUnsignedLong(h1) + Integer.toUnsignedLong(s1) + (c ushr 32)
        h1 = c.toInt()
        c = Integer.toUnsignedLong(h2) + Integer.toUnsignedLong(s2) + (c ushr 32)
        h2 = c.toInt()
        c = Integer.toUnsignedLong(h3) + Integer.toUnsignedLong(s3) + (c ushr 32)
        h3 = c.toInt()

        writeIntLE(h0, tag, offset)
        writeIntLE(h1, tag, offset + 4)
        writeIntLE(h2, tag, offset + 8)
        writeIntLE(h3, tag, offset + 12)

        finished = true
        reset()
    }

    fun reset() {
        r0 = 0; r1 = 0; r2 = 0; r3 = 0; r4 = 0
        s0 = 0; s1 = 0; s2 = 0; s3 = 0
        h0 = 0; h1 = 0; h2 = 0; h3 = 0; h4 = 0
        buffer.fill(0)
        bufferPos = 0
    }

    private fun processBlock(block: ByteArray, offset: Int, isFinal: Boolean) {
        val t0 = readIntLE(block, offset)
        val t1 = readIntLE(block, offset + 4)
        val t2 = readIntLE(block, offset + 8)
        val t3 = readIntLE(block, offset + 12)

        val hibit = if (isFinal && bufferPos < BLOCK_SIZE) 0 else (1 shl 24)

        val d0 = Integer.toUnsignedLong(h0) + (t0.toLong() and 0x03ffffffL)
        val d1 = Integer.toUnsignedLong(h1) + ((((t0 ushr 26) or (t1 shl 6)).toLong()) and 0x03ffffffL)
        val d2 = Integer.toUnsignedLong(h2) + ((((t1 ushr 20) or (t2 shl 12)).toLong()) and 0x03ffffffL)
        val d3 = Integer.toUnsignedLong(h3) + ((((t2 ushr 14) or (t3 shl 18)).toLong()) and 0x03ffffffL)
        val d4 = Integer.toUnsignedLong(h4) + (((t3 ushr 8) or hibit).toLong() and 0xffffffffL)

        val r0L = r0.toLong() and 0xffffffffL
        val r1L = r1.toLong() and 0xffffffffL
        val r2L = r2.toLong() and 0xffffffffL
        val r3L = r3.toLong() and 0xffffffffL
        val r4L = r4.toLong() and 0xffffffffL

        var c: Long = 0
        c = d0 * r0L
        c += d1 * (r4L * 5)
        c += d2 * (r3L * 5)
        c += d3 * (r2L * 5)
        c += d4 * (r1L * 5)
        h0 = c.toInt() and 0x03ffffff
        c = c ushr 26

        c += d0 * r1L
        c += d1 * r0L
        c += d2 * (r4L * 5)
        c += d3 * (r3L * 5)
        c += d4 * (r2L * 5)
        h1 = c.toInt() and 0x03ffffff
        c = c ushr 26

        c += d0 * r2L
        c += d1 * r1L
        c += d2 * r0L
        c += d3 * (r4L * 5)
        c += d4 * (r3L * 5)
        h2 = c.toInt() and 0x03ffffff
        c = c ushr 26

        c += d0 * r3L
        c += d1 * r2L
        c += d2 * r1L
        c += d3 * r0L
        c += d4 * (r4L * 5)
        h3 = c.toInt() and 0x03ffffff
        c = c ushr 26

        c += d0 * r4L
        c += d1 * r3L
        c += d2 * r2L
        c += d3 * r1L
        c += d4 * r0L
        h4 = c.toInt() and 0x03ffffff
        c = c ushr 26

        h0 += (c * 5).toInt()
        h1 += h0 ushr 26
        h0 = h0 and 0x03ffffff
    }

    private fun readIntLE(buf: ByteArray, offset: Int): Int =
        (buf[offset].toInt() and 0xff) or
            ((buf[offset + 1].toInt() and 0xff) shl 8) or
            ((buf[offset + 2].toInt() and 0xff) shl 16) or
            ((buf[offset + 3].toInt() and 0xff) shl 24)

    private fun writeIntLE(value: Int, buf: ByteArray, offset: Int) {
        buf[offset] = value.toByte()
        buf[offset + 1] = (value ushr 8).toByte()
        buf[offset + 2] = (value ushr 16).toByte()
        buf[offset + 3] = (value ushr 24).toByte()
    }
}
