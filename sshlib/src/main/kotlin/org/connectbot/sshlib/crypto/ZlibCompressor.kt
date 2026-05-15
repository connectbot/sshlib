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
import java.util.zip.Deflater
import java.util.zip.Inflater

internal class ZlibCompressor : PacketCompressor {
    companion object {
        // Max decompressed size per packet. Prevents decompression-bomb DoS from a malicious server.
        internal const val MAX_UNCOMPRESSED_SIZE = 512 * 1024
    }

    private val deflater = Deflater(5)
    private val inflater = Inflater()

    override fun compress(data: ByteArray): ByteArray {
        deflater.setInput(data)

        val buffer = ByteArray(maxOf(64, data.size + 64))
        var totalOut = 0

        var output = buffer
        while (true) {
            val count = deflater.deflate(output, totalOut, output.size - totalOut, Deflater.SYNC_FLUSH)
            totalOut += count
            if (count == 0) break
            if (totalOut == output.size) {
                output = output.copyOf(output.size * 2)
            }
        }

        return output.copyOf(totalOut)
    }

    override fun uncompress(data: ByteArray): ByteArray {
        inflater.setInput(data)

        val buffer = ByteArray(maxOf(64, data.size * 2))
        var totalOut = 0

        var output = buffer
        while (true) {
            val count = inflater.inflate(output, totalOut, output.size - totalOut)
            totalOut += count
            if (count == 0) break
            if (totalOut > MAX_UNCOMPRESSED_SIZE) {
                throw SshException("Decompressed packet exceeds maximum allowed size ($MAX_UNCOMPRESSED_SIZE bytes)")
            }
            if (totalOut == output.size) {
                val newSize = minOf(output.size * 2, MAX_UNCOMPRESSED_SIZE + 1)
                output = output.copyOf(newSize)
            }
        }

        return output.copyOf(totalOut)
    }
}
