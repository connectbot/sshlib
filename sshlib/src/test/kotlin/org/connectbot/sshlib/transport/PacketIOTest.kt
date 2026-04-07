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
}
