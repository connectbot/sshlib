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

    fun contextTag(tag: Int, init: DerWriter.() -> Unit) {
        val child = DerWriter()
        child.init()
        val content = child.toByteArray()
        writeTag(0xA0 or tag, content)
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
        readExpectedTag(0x30, "SEQUENCE")
        val length = readLength()
        requireAvailable(length, "SEQUENCE")
        val end = data.position() + length

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

    fun hasRemaining(): Boolean = data.hasRemaining()

    fun readInteger(): BigInteger {
        readExpectedTag(0x02, "INTEGER")
        val bytes = readBytes(readLength(), "INTEGER", allowEmpty = false)
        if (bytes.size > 1) {
            val first = bytes[0].toInt() and 0xFF
            val second = bytes[1].toInt() and 0xFF
            if (first == 0x00 && second and 0x80 == 0) {
                throw SshException("INTEGER has redundant leading zero")
            }
            if (first == 0xFF && second and 0x80 != 0) {
                throw SshException("INTEGER has redundant leading 0xff")
            }
        }
        return BigInteger(bytes)
    }

    fun readOctetString(): ByteArray {
        readExpectedTag(0x04, "OCTET STRING")
        return readBytes(readLength(), "OCTET STRING")
    }

    fun readBitString(): ByteArray {
        readExpectedTag(0x03, "BIT STRING")
        val length = readLength()
        if (length == 0) {
            throw SshException("BIT STRING must include an unused-bits octet")
        }
        requireAvailable(length, "BIT STRING")
        val unusedBits = data.get().toInt() and 0xFF
        if (unusedBits != 0) {
            throw SshException("Non-zero unused bits ($unusedBits) in BIT STRING not supported")
        }
        return readBytes(length - 1, "BIT STRING")
    }

    fun readObjectIdentifier(): ByteArray {
        readExpectedTag(0x06, "OBJECT IDENTIFIER")
        return readBytes(readLength(), "OBJECT IDENTIFIER", allowEmpty = false)
    }

    fun peekTag(): Int {
        if (!data.hasRemaining()) return -1
        val tag = data.get(data.position()).toInt() and 0xFF
        return tag
    }

    fun <T> readContextTag(tag: Int, block: (DerReader) -> T): T {
        val expectedTag = 0xA0 or tag
        readExpectedTag(expectedTag, "context tag [$tag]")
        val length = readLength()
        requireAvailable(length, "context tag [$tag]")
        val end = data.position() + length

        val oldLimit = data.limit()
        data.limit(end)

        try {
            val result = block(this)
            if (data.position() != end) {
                throw SshException("Context tag [$tag] has ${end - data.position()} unconsumed bytes")
            }
            return result
        } finally {
            data.limit(oldLimit)
            data.position(end)
        }
    }

    fun skipTag() {
        readByte("DER tag")
        val length = readLength()
        requireAvailable(length, "DER value")
        data.position(data.position() + length)
    }

    private fun readLength(): Int {
        val first = readByte("DER length")
        if (first < 128) {
            return first
        }
        val octets = first and 0x7F
        if (octets == 0) {
            throw SshException("Indefinite lengths are not valid DER")
        }
        if (octets > Int.SIZE_BYTES) {
            throw SshException("DER length uses too many octets: $octets")
        }
        if (octets > data.remaining()) {
            throw SshException("Truncated DER length")
        }

        val firstLengthOctet = readByte("DER length")
        if (firstLengthOctet == 0) {
            throw SshException("DER length has redundant leading zero")
        }

        var length = firstLengthOctet.toLong()
        repeat(octets - 1) {
            length = (length shl 8) or readByte("DER length").toLong()
        }
        if (length < 128) {
            throw SshException("DER length is not minimally encoded")
        }
        if (length > Int.MAX_VALUE) {
            throw SshException("DER length exceeds supported size: $length")
        }
        return length.toInt()
    }

    private fun readExpectedTag(expectedTag: Int, name: String) {
        val actualTag = readByte("$name tag")
        if (actualTag != expectedTag) {
            throw SshException("Expected $name (0x${expectedTag.toString(16)}) but got 0x${actualTag.toString(16)}")
        }
    }

    private fun readByte(description: String): Int {
        if (!data.hasRemaining()) {
            throw SshException("Truncated $description")
        }
        return data.get().toInt() and 0xFF
    }

    private fun requireAvailable(length: Int, description: String) {
        if (length > data.remaining()) {
            throw SshException(
                "$description length $length exceeds remaining DER data (${data.remaining()} bytes)",
            )
        }
    }

    private fun readBytes(length: Int, description: String, allowEmpty: Boolean = true): ByteArray {
        if (!allowEmpty && length == 0) {
            throw SshException("$description must not be empty")
        }
        requireAvailable(length, description)
        return ByteArray(length).also(data::get)
    }
}
