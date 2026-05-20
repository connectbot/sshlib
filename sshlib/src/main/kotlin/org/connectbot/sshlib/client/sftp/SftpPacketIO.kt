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

package org.connectbot.sshlib.client.sftp

import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SshSession
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * SFTP packet framing over an SSH session channel.
 *
 * SFTP packets are length-prefixed: `uint32 length + byte type + payload`.
 * The length field counts everything after itself (type + payload).
 *
 * SSH channel data arrives in arbitrary chunks that may not align with SFTP
 * packet boundaries. This class accumulates bytes until a complete packet
 * is available.
 */
internal class SftpPacketIO(private val session: SshSession) {
    private val buffer = ByteArrayOutputStream()
    private var bufferedBytes = ByteArray(0)
    private var bufferedOffset = 0
    private var bufferedLength = 0

    /**
     * Read a complete SFTP packet. Blocks (suspends) until enough data arrives.
     *
     * Returns a sealed [SftpResult] rather than throwing — network errors and
     * malformed packets are normal failure modes that callers should handle
     * explicitly. (Reviewed by @kruton on PR #112: Kotlin library APIs
     * shouldn't throw for things they can manage themselves.)
     */
    suspend fun readPacket(): SftpResult<SftpRawPacket> {
        return try {
            // Read the 4-byte length prefix
            val lengthBytes = readExact(4)
            val length = ByteBuffer.wrap(lengthBytes).int
            if (length < 1 || length > MAX_PACKET_SIZE) {
                return SftpResult.ProtocolError("Invalid SFTP packet length: $length")
            }

            // Read the packet body (type + payload)
            val body = readExact(length)
            val type = body[0].toInt() and 0xFF
            val payload = body.copyOfRange(1, body.size)
            SftpResult.Success(SftpRawPacket(type, payload))
        } catch (e: ChannelClosedException) {
            SftpResult.IoError(e)
        } catch (e: Exception) {
            SftpResult.IoError(e)
        }
    }

    /**
     * Write an SFTP packet with the given type and payload.
     *
     * Returns [SftpResult.Success] on send or [SftpResult.IoError] if the
     * underlying SSH session write fails.
     */
    suspend fun writePacket(type: Int, payload: ByteArray): SftpResult<Unit> = try {
        val length = 1 + payload.size // type byte + payload
        val packet = ByteBuffer.allocate(4 + length)
        packet.putInt(length)
        packet.put(type.toByte())
        packet.put(payload)
        session.write(packet.array())
        SftpResult.Success(Unit)
    } catch (e: Exception) {
        SftpResult.IoError(e)
    }

    /**
     * Read exactly [count] bytes from the session, accumulating across
     * multiple channel data chunks as needed. Throws [ChannelClosedException]
     * if the channel closes mid-packet — callers (only [readPacket]) catch
     * and translate to [SftpResult.IoError]. Kept private so the throw
     * doesn't leak past the API surface.
     */
    private suspend fun readExact(count: Int): ByteArray {
        val result = ByteArray(count)
        var filled = 0

        // Drain any leftover buffered data first
        if (bufferedLength > 0) {
            val toCopy = minOf(count, bufferedLength)
            System.arraycopy(bufferedBytes, bufferedOffset, result, 0, toCopy)
            bufferedOffset += toCopy
            bufferedLength -= toCopy
            filled += toCopy
        }

        // Read from the session until we have enough
        while (filled < count) {
            val data = session.read()
                ?: throw ChannelClosedException("SSH channel closed before complete SFTP packet")

            val toCopy = minOf(count - filled, data.size)
            System.arraycopy(data, 0, result, filled, toCopy)
            filled += toCopy

            // Buffer any leftover bytes for the next readExact call
            if (toCopy < data.size) {
                bufferedBytes = data
                bufferedOffset = toCopy
                bufferedLength = data.size - toCopy
            }
        }

        return result
    }

    companion object {
        /** Maximum SFTP packet size (256KB — generous limit). */
        private const val MAX_PACKET_SIZE = 256 * 1024
    }
}

/**
 * Internal exception used by [SftpPacketIO.readExact] to signal a closed
 * channel mid-packet. Caught by [SftpPacketIO.readPacket] and translated
 * into [SftpResult.IoError]; never escapes this file.
 */
internal class ChannelClosedException(message: String) : Exception(message)

/**
 * Raw SFTP packet with type byte and payload (without the length prefix).
 */
internal data class SftpRawPacket(val type: Int, val payload: ByteArray) {
    override fun equals(other: Any?): Boolean = other is SftpRawPacket && type == other.type && payload.contentEquals(other.payload)

    override fun hashCode(): Int = 31 * type + payload.contentHashCode()
}

internal class SftpProtocolException(message: String) : Exception(message)
