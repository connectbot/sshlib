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

package org.connectbot.sshlib.client

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith

class ForwardingChannelTest {

    private fun createChannel(
        connection: SshConnection = mockk(relaxed = true),
        remoteWindowSize: Long = 64 * 1024,
        maxPacketSize: Int = 32 * 1024,
        initialWindowSize: Int = 256 * 1024,
    ): Pair<ForwardingChannel, SshConnection> {
        val channel = ForwardingChannel(
            connection = connection,
            connectionScope = CoroutineScope(UnconfinedTestDispatcher()),
            localChannelNumber = 0,
            remoteChannelNumber = 1,
            maxPacketSize = maxPacketSize,
            remoteWindowSizeInitial = remoteWindowSize,
            initialWindowSize = initialWindowSize,
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
        coVerify(exactly = 0) { conn.sendWindowAdjust(any(), any()) }
        channel.incomingData.receive()

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
    fun `onEof closes incomingData channel`() = runTest {
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
    fun `remote close preserves unread incoming data until consumed`() = runTest {
        val (channel, conn) = createChannel()
        val first = "first".toByteArray()
        val second = "second".toByteArray()

        channel.onData(first)
        channel.onData(second)
        channel.onClose()

        assertArrayEquals(first, channel.incomingData.receive())
        assertArrayEquals(second, channel.incomingData.receive())
        assertTrue(channel.incomingData.receiveCatching().isClosed)
        coVerify(exactly = 0) { conn.sendWindowAdjust(any(), any()) }
    }

    @Test
    fun `explicit close after remote close discards abandoned incoming data`() = runTest {
        val (channel, _) = createChannel()

        channel.onData("abandoned".toByteArray())
        channel.onClose()
        channel.close()

        assertTrue(channel.incomingData.receiveCatching().isClosed)
    }

    @Test
    fun `sendData chunks data by maxPacketSize`() = runTest {
        val conn = mockk<SshConnection>(relaxed = true)
        val sentChunks = mutableListOf<ByteArray>()
        coEvery { conn.sendChannelData(any(), capture(sentChunks)) } returns Unit

        val channel = ForwardingChannel(
            connection = conn,
            connectionScope = CoroutineScope(UnconfinedTestDispatcher()),
            localChannelNumber = 0,
            remoteChannelNumber = 1,
            maxPacketSize = 10,
            remoteWindowSizeInitial = 100,
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

    @Test
    fun `data after remote EOF has no delivery side effect`() = runTest {
        val (channel, _) = createChannel()

        channel.onEof()

        assertFailsWith<SshException> {
            channel.onData(byteArrayOf(1))
        }
        assertTrue(channel.incomingData.isClosedForReceive)
    }
}
