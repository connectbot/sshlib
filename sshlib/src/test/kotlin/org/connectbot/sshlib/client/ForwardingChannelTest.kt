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

package org.connectbot.sshlib.client

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class ForwardingChannelTest {

    private fun createChannel(
        connection: SshConnection = mockk(relaxed = true),
        remoteWindowSize: Long = 64 * 1024,
        maxPacketSize: Int = 32 * 1024,
        initialWindowSize: Int = 256 * 1024
    ): Pair<ForwardingChannel, SshConnection> {
        val channel = ForwardingChannel(
            connection = connection,
            localChannelNumber = 0,
            remoteChannelNumber = 1,
            maxPacketSize = maxPacketSize,
            remoteWindowSize = remoteWindowSize,
            initialWindowSize = initialWindowSize
        )
        return channel to connection
    }

    @Test
    fun `onData delivers data to incomingData channel`() = runTest {
        val (channel, _) = createChannel()
        val testData = "hello".toByteArray()

        channel.onData(testData)

        val received = channel.incomingData.tryReceive().getOrNull()
        assertArrayEquals(testData, received)
    }

    @Test
    fun `onData sends window adjust when below threshold`() = runTest {
        val (channel, conn) = createChannel(initialWindowSize = 128)
        val data = ByteArray(100)

        channel.onData(data)

        coVerify { conn.sendWindowAdjust(1, any()) }
    }

    @Test
    fun `onWindowAdjust increases remote window`() = runTest {
        val (channel, conn) = createChannel(remoteWindowSize = 100)
        val data = ByteArray(50)

        channel.sendData(data)
        channel.onWindowAdjust(200)

        val moreData = ByteArray(50)
        channel.sendData(moreData)

        coVerify(exactly = 2) { conn.sendChannelData(1, any()) }
    }

    @Test
    fun `onEof closes incomingData channel`() {
        val (channel, _) = createChannel()

        channel.onEof()

        assertTrue(channel.incomingData.isClosedForReceive)
    }

    @Test
    fun `onClose sets isOpen to false and closes incomingData`() = runTest {
        val (channel, _) = createChannel()
        assertTrue(channel.isOpen)

        channel.onClose()

        assertFalse(channel.isOpen)
        assertTrue(channel.incomingData.isClosedForReceive)
    }

    @Test
    fun `sendData chunks data by maxPacketSize`() = runTest {
        val conn = mockk<SshConnection>(relaxed = true)
        val sentChunks = mutableListOf<ByteArray>()
        coEvery { conn.sendChannelData(any(), capture(sentChunks)) } returns Unit

        val channel = ForwardingChannel(
            connection = conn,
            localChannelNumber = 0,
            remoteChannelNumber = 1,
            maxPacketSize = 10,
            remoteWindowSize = 100
        )

        val data = ByteArray(25) { it.toByte() }
        channel.sendData(data)

        assertEquals(3, sentChunks.size)
        assertEquals(10, sentChunks[0].size)
        assertEquals(10, sentChunks[1].size)
        assertEquals(5, sentChunks[2].size)

        val combined = sentChunks.flatMap { it.toList() }.toByteArray()
        assertArrayEquals(data, combined)
    }

    @Test
    fun `sendEof sends EOF to connection`() = runTest {
        val (channel, conn) = createChannel()

        channel.sendEof()

        coVerify { conn.sendChannelEof(1) }
    }

    @Test
    fun `close sends channel close and marks not open`() = runTest {
        val (channel, conn) = createChannel()
        assertTrue(channel.isOpen)

        channel.close()

        assertFalse(channel.isOpen)
        coVerify { conn.sendChannelClose(1) }
    }

    @Test
    fun `close is idempotent`() = runTest {
        val (channel, conn) = createChannel()

        channel.close()
        channel.close()

        coVerify(exactly = 1) { conn.sendChannelClose(1) }
    }
}
