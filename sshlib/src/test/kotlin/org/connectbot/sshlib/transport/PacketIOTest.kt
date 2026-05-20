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

package org.connectbot.sshlib.transport

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.protocol.SshEnums
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class PacketIOTest {

    @Test
    fun `unencrypted round trip works`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)

        val messageType = SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt()
        // SSH_MSG_IGNORE payload is a byte_string (uint32 length + data)
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()

        io.writePacket(messageType, payload)

        val writtenData = transport.getWrittenData()
        val readTransport = ByteArrayTransport(writtenData)
        val readIO = PacketIO(readTransport)

        val parsed = readIO.readPacket()
        assertEquals(SshEnums.MessageType.SSH_MSG_IGNORE, parsed.messageType())
    }

    @Test
    fun `readBanner handles valid banner`() = runBlocking {
        val bannerLine = "2.0-TestServer_1.0"
        val banner = "SSH-$bannerLine\r\n"
        val transport = ByteArrayTransport(banner.toByteArray())
        val io = PacketIO(transport)

        val parsedBanner = io.readBanner()
        // IdBanner._read uses readBytesTerm(10, false, true, true)
        // This includes \r if present before \n
        assertEquals(bannerLine + "\r", parsedBanner.protoVersion())
    }

    @Test
    fun `readBanner throws on too long banner`() {
        val longBanner = "A".repeat(300) + "\r\n"
        val transport = ByteArrayTransport(longBanner.toByteArray())
        val io = PacketIO(transport)

        assertThrows(TransportException::class.java) {
            runBlocking {
                io.readBanner()
            }
        }
    }

    @Test
    fun `readPacket throws on invalid packet length`() {
        // Packet length too small (MIN_PACKET_LENGTH is 6)
        val invalidLength = byteArrayOf(0, 0, 0, 1)
        val transport = ByteArrayTransport(invalidLength)
        val io = PacketIO(transport)

        assertThrows(TransportException::class.java) {
            runBlocking {
                io.readPacket()
            }
        }
    }

    @Test
    fun `readPacket throws on too large packet length`() {
        // Packet length too large (MAX_PACKET_LENGTH is 35000)
        val length = 40000
        val invalidLength = byteArrayOf(
            ((length shr 24) and 0xFF).toByte(),
            ((length shr 16) and 0xFF).toByte(),
            ((length shr 8) and 0xFF).toByte(),
            (length and 0xFF).toByte(),
        )
        val transport = ByteArrayTransport(invalidLength)
        val io = PacketIO(transport)

        assertThrows(TransportException::class.java) {
            runBlocking {
                io.readPacket()
            }
        }
    }

    @Test
    fun `reset sequence numbers works`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)

        io.resetSendSequenceNumber()
        io.resetReceiveSequenceNumber()
    }

    @Test
    fun `bytesSentOnWire tracks unencrypted write`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)

        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()
        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), payload)
        assertTrue(io.bytesSentOnWire > 0)
        assertEquals(io.bytesSentOnWire, transport.getWrittenData().size.toLong())
    }

    @Test
    fun `bytesReceivedOnWire tracks unencrypted read`() = runBlocking {
        val transport = ByteArrayTransport()
        val writer = PacketIO(transport)
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()
        writer.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), payload)

        val readTransport = ByteArrayTransport(transport.getWrittenData())
        val reader = PacketIO(readTransport)
        reader.readPacket()

        assertEquals(transport.getWrittenData().size.toLong(), reader.bytesReceivedOnWire)
    }

    @Test
    fun `resetByteCounters zeroes both counters`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()
        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), payload)
        assertTrue(io.bytesSentOnWire > 0)

        io.resetByteCounters()
        assertEquals(0L, io.bytesSentOnWire)
        assertEquals(0L, io.bytesReceivedOnWire)
    }

    // calculatePaddingLength: totalLength = 4 + 1 + (1 + payload.size) = 6 + payload.size.
    // With blockSize=8: raw = if (totalLength%8==0) 8 else 8-(totalLength%8). Bump by 8 if raw<4.
    // Verifying the exact padding_length byte at wire[4] kills MathMutator and ConditionalsBoundaryMutator survivors.

    private fun writtenPaddingLength(payloadSize: Int): Int = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)
        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), ByteArray(payloadSize))
        transport.getWrittenData()[4].toInt() and 0xFF
    }

    @Test
    fun `calculatePaddingLength produces minimum 4 bytes of padding`() {
        for (payloadSize in 0..64) {
            val padding = writtenPaddingLength(payloadSize)
            assertTrue(padding >= 4, "payload=$payloadSize: padding $padding < 4")
        }
    }

    @Test
    fun `calculatePaddingLength result aligns total wire packet to multiple of 8`() {
        // totalLength in RFC 4253 = 4(length field) + 1(padding_length) + 1(msg_type) + payloadSize + padding
        // = 6 + payloadSize + padding must be multiple of 8
        for (payloadSize in 0..64) {
            val padding = writtenPaddingLength(payloadSize)
            val wireTotal = 6 + payloadSize + padding
            assertEquals(0, wireTotal % 8, "payload=$payloadSize: wireTotal $wireTotal not multiple of 8")
        }
    }

    @Test
    fun `calculatePaddingLength payload 2 aligns without bump`() {
        // totalLength=8 (2+6), 8%8=0, raw=8, ≥4 → no bump → padding=8
        assertEquals(8, writtenPaddingLength(2))
    }

    @Test
    fun `calculatePaddingLength payload 3 gives 7`() {
        // totalLength=9, 9%8=1, raw=7, ≥4 → padding=7
        assertEquals(7, writtenPaddingLength(3))
    }

    @Test
    fun `calculatePaddingLength payload 6 gives exactly 4 without bump`() {
        // totalLength=12, 12%8=4, raw=4, not <4 → padding=4 (boundary: mutant with <=4 would bump to 12)
        assertEquals(4, writtenPaddingLength(6))
    }

    @Test
    fun `calculatePaddingLength payload 7 gets bumped because raw is 3`() {
        // totalLength=13, 13%8=5, raw=3, <4 → bump: 3+8=11
        assertEquals(11, writtenPaddingLength(7))
    }

    @Test
    fun `calculatePaddingLength payload 0 gets bumped because raw is 2`() {
        // totalLength=6, 6%8=6, raw=2, <4 → bump: 2+8=10
        assertEquals(10, writtenPaddingLength(0))
    }
}
