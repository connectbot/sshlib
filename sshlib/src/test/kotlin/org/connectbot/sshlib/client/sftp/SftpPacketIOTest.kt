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

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SshSession
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SftpPacketIOTest {

    @Test
    fun `readPacket rejects invalid lengths`() {
        runBlocking {
            val tooSmall = FakeSshSession()
            tooSmall.enqueue(ByteBuffer.allocate(4).putInt(0).array())
            assertIs<SftpResult.ProtocolError>(SftpPacketIO(tooSmall).readPacket())

            val tooLarge = FakeSshSession()
            tooLarge.enqueue(ByteBuffer.allocate(4).putInt(256 * 1024 + 1).array())
            assertIs<SftpResult.ProtocolError>(SftpPacketIO(tooLarge).readPacket())
        }
    }

    @Test
    fun `readPacket reports closed channel before packet completes`() = runBlocking {
        val session = FakeSshSession()
        session.enqueue(ByteBuffer.allocate(4).putInt(4).array())
        session.closeReads()

        val result = SftpPacketIO(session).readPacket()

        assertIs<SftpResult.IoError>(result)
        assertEquals("ChannelClosedException", result.cause::class.simpleName)
    }

    @Test
    fun `readPacket buffers extra bytes for following packet`() = runBlocking {
        val session = FakeSshSession()
        session.enqueue(packet(10, byteArrayOf(1)) + packet(11, byteArrayOf(2, 3)))
        val packetIO = SftpPacketIO(session)

        val first = assertIs<SftpResult.Success<SftpRawPacket>>(packetIO.readPacket()).value
        val second = assertIs<SftpResult.Success<SftpRawPacket>>(packetIO.readPacket()).value

        assertEquals(10, first.type)
        assertContentEquals(byteArrayOf(1), first.payload)
        assertEquals(11, second.type)
        assertContentEquals(byteArrayOf(2, 3), second.payload)
    }

    @Test
    fun `writePacket serializes length type and payload`() = runBlocking {
        val session = FakeSshSession()

        val result = SftpPacketIO(session).writePacket(99, byteArrayOf(1, 2, 3))

        assertEquals(SftpResult.Success(Unit), result)
        assertContentEquals(byteArrayOf(0, 0, 0, 4, 99, 1, 2, 3), session.writes.single())
    }

    private fun packet(type: Int, payload: ByteArray): ByteArray {
        val packet = ByteBuffer.allocate(4 + 1 + payload.size)
        packet.putInt(1 + payload.size)
        packet.put(type.toByte())
        packet.put(payload)
        return packet.array()
    }

    private class FakeSshSession : SshSession {
        private val reads = Channel<ByteArray>(Channel.UNLIMITED)
        val writes = mutableListOf<ByteArray>()

        override val localChannelNumber: Int = 1
        override val remoteChannelNumber: Int = 2
        override val isOpen: Boolean = true
        override val stdout: ReceiveChannel<ByteArray> = Channel()
        override val stderr: ReceiveChannel<ByteArray> = Channel()

        fun enqueue(data: ByteArray) {
            reads.trySend(data).getOrThrow()
        }

        fun closeReads() {
            reads.close()
        }

        override suspend fun requestPty(
            terminalType: String,
            widthChars: Int,
            heightRows: Int,
            widthPixels: Int,
            heightPixels: Int,
            terminalModes: ByteArray,
        ): Boolean = true

        override suspend fun resizeTerminal(
            widthChars: Int,
            heightRows: Int,
            widthPixels: Int,
            heightPixels: Int,
        ): Boolean = true

        override suspend fun requestShell(): Boolean = true

        override suspend fun requestExec(command: String): Boolean = true

        override suspend fun requestSubsystem(name: String): Boolean = true

        override suspend fun write(data: ByteArray) {
            writes += data
        }

        override suspend fun read(): ByteArray? = reads.receiveCatching().getOrNull()

        override suspend fun readExtended(): Pair<Int, ByteArray>? = null

        override suspend fun sendEof() = Unit

        override fun close() = Unit
    }
}
