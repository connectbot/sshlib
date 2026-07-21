/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

package org.connectbot.sshlib.client.sftp

import java.nio.ByteBuffer

internal class SftpDecodeException(message: String) : Exception(message)

/** Checked readers for server-controlled SFTP response fields. */
internal object SftpDecoder {
    private const val MAX_FIELD_SIZE = 256 * 1024

    fun readInt(buf: ByteBuffer, field: String): Int {
        requireRemaining(buf, Int.SIZE_BYTES, field)
        return buf.int
    }

    fun readLong(buf: ByteBuffer, field: String): Long {
        requireRemaining(buf, Long.SIZE_BYTES, field)
        return buf.long
    }

    fun readString(buf: ByteBuffer, field: String): ByteArray {
        val length = readInt(buf, "$field length")
        if (length < 0) throw SftpDecodeException("Negative $field length: $length")
        if (length > MAX_FIELD_SIZE) throw SftpDecodeException("$field length exceeds limit: $length")
        requireRemaining(buf, length, field)
        return ByteArray(length).also(buf::get)
    }

    fun readCount(buf: ByteBuffer, field: String, minimumElementSize: Int): Int {
        val count = readInt(buf, field)
        if (count < 0) throw SftpDecodeException("Negative $field: $count")
        val maximumCount = buf.remaining() / minimumElementSize
        if (count > maximumCount) {
            throw SftpDecodeException("$field $count exceeds remaining packet capacity $maximumCount")
        }
        return count
    }

    private fun requireRemaining(buf: ByteBuffer, length: Int, field: String) {
        if (length > buf.remaining()) {
            throw SftpDecodeException("$field length $length exceeds remaining response data ${buf.remaining()}")
        }
    }
}
