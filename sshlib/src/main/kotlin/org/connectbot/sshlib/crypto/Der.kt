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
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer

/**
 * Helper to create a DER encoded byte array using the DSL.
 */
internal fun encodeDer(init: DerWriter.() -> Unit): ByteArray {
    val writer = DerWriter()
    writer.init()
    return writer.toByteArray()
}

/**
 * Writes DER encoded data using a DSL.
 *
 * Usage:
 * ```
 * encodeDer {
 *     sequence {
 *         integer(BigInteger.valueOf(1))
 *         octetString(byteArrayOf(0x01, 0x02))
 *     }
 * }
 * ```
 */
internal class DerWriter {
    private val buffer = ByteArrayOutputStream()

    fun toByteArray(): ByteArray = buffer.toByteArray()

    fun sequence(init: DerWriter.() -> Unit) {
        val child = DerWriter()
        child.init()
        val content = child.toByteArray()
        writeTag(0x30, content)
    }

    fun integer(i: BigInteger) {
        writeTag(0x02, i.toByteArray())
    }

    fun bitString(bytes: ByteArray) {
        val content = ByteArray(1 + bytes.size)
        content[0] = 0x00 // zero unused bits
        System.arraycopy(bytes, 0, content, 1, bytes.size)
        writeTag(0x03, content)
    }

    fun octetString(bytes: ByteArray) {
        writeTag(0x04, bytes)
    }

    fun objectIdentifier(oid: ByteArray) {
        writeTag(0x06, oid)
    }

    fun nullValue() {
        buffer.write(0x05)
        buffer.write(0x00)
    }

    private fun writeTag(tag: Int, content: ByteArray) {
        buffer.write(tag)
        writeLength(content.size)
        buffer.write(content)
    }

    private fun writeLength(length: Int) {
        if (length < 128) {
            buffer.write(length)
        } else {
            val lenBytes = ByteArrayOutputStream()
            var l = length
            while (l > 0) {
                lenBytes.write(l and 0xFF)
                l = l ushr 8
            }
            val lenContent = lenBytes.toByteArray().reversedArray()
            buffer.write(0x80 or lenContent.size)
            buffer.write(lenContent)
        }
    }
}

/**
 * Reads DER encoded data.
 *
 * Usage:
 * ```
 * val reader = DerReader(bytes)
 * reader.readSequence { seq ->
 *     val i = seq.readInteger()
 * }
 * ```
 */
internal class DerReader(private val data: ByteBuffer) {
    constructor(bytes: ByteArray) : this(ByteBuffer.wrap(bytes))

    fun <T> readSequence(block: (DerReader) -> T): T {
        val tag = data.get().toInt() and 0xFF
        if (tag != 0x30) {
            throw SshException("Expected SEQUENCE (0x30) but got 0x${tag.toString(16)}")
        }
        val length = readLength()
        val end = data.position() + length

        // Create a limit slice for the sequence content
        val oldLimit = data.limit()
        data.limit(end)

        try {
            val result = block(this)
            if (data.position() != end) {
                throw SshException("SEQUENCE has ${end - data.position()} unconsumed bytes")
            }
            return result
        } finally {
            data.limit(oldLimit)
            data.position(end)
        }
    }

    fun ensureFullyConsumed() {
        if (data.hasRemaining()) {
            throw SshException("${data.remaining()} trailing bytes after DER data")
        }
    }

    fun readInteger(): BigInteger {
        val tag = data.get().toInt() and 0xFF
        if (tag != 0x02) {
            throw SshException("Expected INTEGER (0x02) but got 0x${tag.toString(16)}")
        }
        val length = readLength()
        val bytes = ByteArray(length)
        data.get(bytes)
        return BigInteger(bytes)
    }

    private fun readLength(): Int {
        val first = data.get().toInt() and 0xFF
        if (first < 128) {
            return first
        }
        val octets = first and 0x7F
        var length = 0
        for (i in 0 until octets) {
            length = (length shl 8) or (data.get().toInt() and 0xFF)
        }
        return length
    }
}
