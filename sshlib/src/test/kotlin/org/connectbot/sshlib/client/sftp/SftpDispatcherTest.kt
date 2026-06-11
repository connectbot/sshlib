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

package org.connectbot.sshlib.client.sftp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SftpStatusCode
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SftpDispatcherTest {

    @Test
    fun `request prepends request id and receives matching response`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)
        dispatcher.startReadLoop(this)

        val response = async { dispatcher.request(10, byteArrayOf(7, 8)) }
        val write = packetIO.awaitWrite()
        val requestId = ByteBuffer.wrap(write.payload, 0, 4).int

        assertEquals(10, write.type)
        assertContentEquals(byteArrayOf(7, 8), write.payload.copyOfRange(4, write.payload.size))

        packetIO.enqueue(SftpResult.Success(packet(20, requestId, byteArrayOf(1, 2, 3))))

        val result = assertIs<SftpResult.Success<SftpRawPacket>>(response.await()).value
        assertEquals(20, result.type)
        assertContentEquals(byteArrayOf(1, 2, 3), result.payload)

        dispatcher.stop()
    }

    @Test
    fun `request returns write protocol server and io failures`() {
        runBlocking {
            val io = IllegalStateException("no channel")
            assertIs<SftpResult.IoError>(
                requestWithWriteResult(SftpResult.IoError(io)),
            )

            assertIs<SftpResult.ProtocolError>(
                requestWithWriteResult(SftpResult.ProtocolError("bad packet")),
            )

            assertIs<SftpResult.ServerError>(
                requestWithWriteResult(SftpResult.ServerError(SftpStatusCode.FAILURE, "server said no")),
            )
        }
    }

    @Test
    fun `read loop skips malformed and unknown responses before matching response`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)
        dispatcher.startReadLoop(this)

        val response = async { dispatcher.request(11, ByteArray(0)) }
        val requestId = ByteBuffer.wrap(packetIO.awaitWrite().payload, 0, 4).int

        packetIO.enqueue(SftpResult.Success(SftpRawPacket(99, byteArrayOf(1, 2, 3))))
        packetIO.enqueue(SftpResult.Success(packet(99, requestId + 1, byteArrayOf(8))))
        packetIO.enqueue(SftpResult.Success(packet(99, requestId, byteArrayOf(9))))

        val result = assertIs<SftpResult.Success<SftpRawPacket>>(response.await()).value
        assertContentEquals(byteArrayOf(9), result.payload)

        dispatcher.stop()
    }

    @Test
    fun `read loop protocol error completes pending request`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)
        dispatcher.startReadLoop(this)

        val response = async { dispatcher.request(12, ByteArray(0)) }
        packetIO.awaitWrite()
        packetIO.enqueue(SftpResult.ProtocolError("short packet"))

        val result = assertIs<SftpResult.IoError>(response.await())
        assertEquals("short packet", result.cause.message)
    }

    @Test
    fun `read loop io error completes pending request`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)
        dispatcher.startReadLoop(this)

        val response = async { dispatcher.request(13, ByteArray(0)) }
        packetIO.awaitWrite()
        packetIO.enqueue(SftpResult.IoError(IllegalStateException("closed")))

        val result = assertIs<SftpResult.IoError>(response.await())
        assertEquals("closed", result.cause.message)
    }

    @Test
    fun `read loop server error exits and pending request times out`() {
        runBlocking {
            val packetIO = FakePacketTransport()
            val dispatcher = SftpDispatcher(packetIO)
            dispatcher.startReadLoop(this)

            val response = async { dispatcher.request(14, ByteArray(0), timeoutMs = 50) }
            packetIO.awaitWrite()
            packetIO.enqueue(SftpResult.ServerError(SftpStatusCode.FAILURE, "framing server error"))

            assertIs<SftpResult.IoError>(response.await())
        }
    }

    @Test
    fun `read loop unexpected exception completes pending request`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)
        dispatcher.startReadLoop(this)

        val response = async { dispatcher.request(15, ByteArray(0)) }
        packetIO.awaitWrite()
        packetIO.enqueueThrow(IllegalArgumentException("boom"))

        val result = assertIs<SftpResult.IoError>(response.await())
        assertEquals("boom", result.cause.message)
    }

    @Test
    fun `stop completes pending request`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)

        val response = async { dispatcher.request(16, ByteArray(0)) }
        packetIO.awaitWrite()
        dispatcher.stop()

        val result = assertIs<SftpResult.IoError>(response.await())
        assertEquals("SFTP session closed", result.cause.message)
    }

    @Test
    fun `writeRaw and readRaw forward packet io results`() = runBlocking {
        val packetIO = FakePacketTransport()
        val dispatcher = SftpDispatcher(packetIO)
        packetIO.enqueue(SftpResult.Success(SftpRawPacket(2, byteArrayOf(3))))

        assertEquals(SftpResult.Success(Unit), dispatcher.writeRaw(1, byteArrayOf(2)))
        assertEquals(SftpResult.Success(SftpRawPacket(2, byteArrayOf(3))), dispatcher.readRaw())
        assertEquals(Write(1, byteArrayOf(2)), packetIO.writes.single())
    }

    private suspend fun requestWithWriteResult(writeResult: SftpResult<Unit>): SftpResult<SftpRawPacket> {
        val packetIO = FakePacketTransport()
        packetIO.writeResult = writeResult
        return SftpDispatcher(packetIO).request(1, ByteArray(0))
    }

    private fun packet(type: Int, requestId: Int, payload: ByteArray): SftpRawPacket {
        val fullPayload = ByteBuffer.allocate(4 + payload.size)
            .putInt(requestId)
            .put(payload)
            .array()
        return SftpRawPacket(type, fullPayload)
    }

    private data class Write(val type: Int, val payload: ByteArray) {
        override fun equals(other: Any?): Boolean = other is Write && type == other.type && payload.contentEquals(other.payload)

        override fun hashCode(): Int = 31 * type + payload.contentHashCode()
    }

    private sealed interface ReadEvent {
        data class Packet(val result: SftpResult<SftpRawPacket>) : ReadEvent
        data class Throw(val cause: Throwable) : ReadEvent
    }

    private class FakePacketTransport : SftpPacketTransport {
        private val readEvents = Channel<ReadEvent>(Channel.UNLIMITED)
        private val firstWrite = CompletableDeferred<Write>()
        val writes = mutableListOf<Write>()
        var writeResult: SftpResult<Unit> = SftpResult.Success(Unit)

        suspend fun awaitWrite(): Write = withTimeout(1_000) {
            while (!firstWrite.isCompleted) {
                delay(1)
            }
            firstWrite.await()
        }

        fun enqueue(result: SftpResult<SftpRawPacket>) {
            assertTrue(readEvents.trySend(ReadEvent.Packet(result)).isSuccess)
        }

        fun enqueueThrow(cause: Throwable) {
            assertTrue(readEvents.trySend(ReadEvent.Throw(cause)).isSuccess)
        }

        override suspend fun readPacket(): SftpResult<SftpRawPacket> = when (val event = readEvents.receive()) {
            is ReadEvent.Packet -> event.result
            is ReadEvent.Throw -> throw event.cause
        }

        override suspend fun writePacket(type: Int, payload: ByteArray): SftpResult<Unit> {
            val write = Write(type, payload)
            writes += write
            firstWrite.complete(write)
            return writeResult
        }
    }
}
