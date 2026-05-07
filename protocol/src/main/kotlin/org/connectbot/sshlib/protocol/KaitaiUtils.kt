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

package org.connectbot.sshlib.protocol

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStruct
import java.nio.BufferOverflowException

/**
 * Serialize a Kaitai struct to a byte array.
 *
 * Kaitai's [ByteBufferKaitaiStream] is fixed-capacity, so the underlying
 * `ByteBuffer.put` throws [BufferOverflowException] if the
 * pre-allocated buffer is too small. We don't have a cheap way to know
 * the encoded size up front, so start at 16 KiB and double on overflow
 * until the message fits or we cross [MAX_BUFFER]. Most SSH messages
 * encode in well under 16 KiB; this only matters for [SshMsgChannelData]
 * carrying near-`maxPacketSize` (32 KiB) of data — e.g. SFTP transfers.
 */
fun KaitaiStruct.ReadWrite.toByteArray(): ByteArray {
    _check()
    var capacity = INITIAL_BUFFER
    while (true) {
        try {
            val io = ByteBufferKaitaiStream(capacity)
            _write(io)
            val size = io.pos()
            io.seek(0)
            return io.readBytes(size.toLong())
        } catch (_: BufferOverflowException) {
            if (capacity >= MAX_BUFFER) throw IllegalStateException("Kaitai message exceeds $MAX_BUFFER byte serialization limit")
            capacity = minOf(capacity * 2, MAX_BUFFER)
        }
    }
}

private const val INITIAL_BUFFER = 1024L * 16
private const val MAX_BUFFER = 1024L * 1024
