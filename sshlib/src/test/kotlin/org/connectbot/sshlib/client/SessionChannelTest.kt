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
import io.mockk.slot
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith

@OptIn(ExperimentalCoroutinesApi::class)
class SessionChannelTest {

    private fun createChannel(
        connection: SshConnection = mockk(relaxed = true),
        initialWindowSize: Int = 64 * 1024,
        connectionScope: CoroutineScope = CoroutineScope(UnconfinedTestDispatcher()),
    ): Pair<SessionChannel, SshConnection> {
        val channel = SessionChannel(
            connection = connection,
            connectionScope = connectionScope,
            localChannelNumber = 0,
            _remoteChannelNumber = 1,
            maxPacketSize = 32 * 1024,
            remoteWindowSizeInitial = 64 * 1024L,
            initialWindowSize = initialWindowSize,
        )
        return channel to connection
    }

    @Test
    fun `resizeTerminal sends window-change request with correct dimensions`() = runTest {
        val requestTypeSlot = slot<String>()
        val wantReplySlot = slot<Boolean>()
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery {
            conn.beginChannelRequest(any(), capture(requestTypeSlot), capture(wantReplySlot), any())
        } returns null

        val (channel, _) = createChannel(conn)

        val result = channel.resizeTerminal(
            widthChars = 120,
            heightRows = 40,
            widthPixels = 960,
            heightPixels = 640,
        )

        assertTrue(result)
        assertEquals("window-change", requestTypeSlot.captured)
        assertFalse(wantReplySlot.captured)
    }

    @Test
    fun `resizeTerminal returns false when request fails`() = runTest {
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.beginChannelRequest(any(), any(), any(), any()) } returns CompletableDeferred(false)

        val (channel, _) = createChannel(conn)

        val result = channel.resizeTerminal(
            widthChars = 80,
            heightRows = 24,
            widthPixels = 0,
            heightPixels = 0,
        )

        assertFalse(result)
    }

    @Test
    fun `resizeTerminal sends to correct remote channel`() = runTest {
        val channelSlot = slot<Int>()
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery {
            conn.beginChannelRequest(capture(channelSlot), any(), any(), any())
        } returns null

        val (channel, _) = createChannel(conn)

        channel.resizeTerminal(80, 24, 0, 0)

        assertEquals(1, channelSlot.captured)
    }

    @Test
    fun `onData delivers data to stdout`() = runTest {
        val (channel, _) = createChannel()
        val testData = "hello".toByteArray()

        channel.onData(testData)

        val received = channel.stdout.tryReceive().getOrNull()
        assertArrayEquals(testData, received)
    }

    @Test
    fun `onData sends window adjust when local window drops below threshold`() = runTest {
        val (channel, conn) = createChannel(initialWindowSize = 128)

        channel.onData(ByteArray(100))
        coVerify(exactly = 0) { conn.sendWindowAdjust(any(), any()) }
        channel.stdout.receive()

        coVerify { conn.sendWindowAdjust(1, any()) }
    }

    @Test
    fun `unconsumed data does not refill local window`() = runTest {
        val (channel, _) = createChannel(initialWindowSize = 128)

        channel.onData(ByteArray(100))

        assertFailsWith<SshException> {
            channel.onData(ByteArray(29))
        }
    }

    @Test
    fun `onExtendedData delivers data to stderr for type 1`() = runTest {
        val (channel, _) = createChannel()
        val testData = "err".toByteArray()

        channel.onExtendedData(1, testData)

        val received = channel.stderr.tryReceive().getOrNull()
        assertArrayEquals(testData, received)
    }

    @Test
    fun `remote close preserves unread stdout until consumed`() = runTest {
        val (channel, conn) = createChannel()
        val first = "first".toByteArray()
        val second = "second".toByteArray()

        channel.onData(first)
        channel.onData(second)
        channel.onClose()

        assertArrayEquals(first, channel.stdout.receive())
        assertArrayEquals(second, channel.stdout.receive())
        assertTrue(channel.stdout.receiveCatching().isClosed)
        coVerify(exactly = 0) { conn.sendWindowAdjust(any(), any()) }
    }

    @Test
    fun `remote close preserves unread stderr and extended data`() = runTest {
        val (channel, _) = createChannel()
        val stderr = "error".toByteArray()
        val extended = "extended".toByteArray()

        channel.onExtendedData(1, stderr)
        channel.onExtendedData(7, extended)
        channel.onClose()

        assertArrayEquals(stderr, channel.stderr.receive())
        val receivedExtended = channel.readExtended()
        assertEquals(7, receivedExtended?.first)
        assertArrayEquals(extended, receivedExtended?.second)
        assertTrue(channel.stderr.receiveCatching().isClosed)
        assertEquals(null, channel.readExtended())
    }

    @Test
    fun `remote EOF preserves unread stdout until consumed`() = runTest {
        val (channel, _) = createChannel()
        val data = "tail".toByteArray()

        channel.onData(data)
        channel.onEof()

        assertArrayEquals(data, channel.stdout.receive())
        assertTrue(channel.stdout.receiveCatching().isClosed)
    }

    @Test
    fun `explicit close after remote close discards abandoned output`() = runTest {
        val (channel, _) = createChannel()

        channel.onData("abandoned".toByteArray())
        channel.onClose()
        channel.close()

        assertTrue(channel.stdout.receiveCatching().isClosed)
    }

    @Test
    fun `close marks channel not open and sends channel close`() = runTest {
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
    fun `onWindowAdjust throws when remote window would exceed max uint32`() = runTest {
        // Start with a large initial window and try to push it over 2^32-1
        val (channel, _) = createChannel(
            connection = mockk(relaxed = true),
            initialWindowSize = 64 * 1024,
        )
        // channel starts with remoteWindowSizeInitial = 64 * 1024; add enough to overflow uint32
        val overflow = (0xFFFFFFFFL - 64 * 1024L) + 1L
        assertFailsWith<SshException> {
            channel.onWindowAdjust(overflow)
        }
    }

    @Test
    fun `onWindowAdjust accepts legitimate adjustment within uint32 range`() = runTest {
        val (channel, _) = createChannel(
            connection = mockk(relaxed = true),
            initialWindowSize = 64 * 1024,
        )
        // Valid: bring window up to exactly 2^32-1
        val maxAdd = 0xFFFFFFFFL - 64 * 1024L
        channel.onWindowAdjust(maxAdd) // should not throw
    }

    @Test
    fun `onWindowAdjust rejects zero adjustment`() = runTest {
        val (channel, _) = createChannel(connection = mockk(relaxed = true))
        assertFailsWith<SshException> {
            channel.onWindowAdjust(0L)
        }
    }

    @Test
    fun `onWindowAdjust rejects negative adjustment`() = runTest {
        val (channel, _) = createChannel(connection = mockk(relaxed = true))
        assertFailsWith<SshException> {
            channel.onWindowAdjust(-1L)
        }
    }

    @Test
    fun `onData rejects data exceeding local window size`() = runTest {
        val (channel, _) = createChannel(initialWindowSize = 1024)
        assertFailsWith<SshException> {
            channel.onData(ByteArray(1025))
        }
    }

    @Test
    fun `onData accepts data exactly filling local window`() = runTest {
        val (channel, _) = createChannel(initialWindowSize = 1024)
        channel.onData(ByteArray(1024))
    }

    @Test
    fun `onExtendedData rejects data exceeding local window size`() = runTest {
        val (channel, _) = createChannel(initialWindowSize = 512)
        assertFailsWith<SshException> {
            channel.onExtendedData(1, ByteArray(513))
        }
    }

    @Test
    fun `data after remote EOF is rejected before delivery`() = runTest {
        val (channel, _) = createChannel()

        channel.onEof()

        assertFailsWith<SshException> {
            channel.onData(byteArrayOf(1))
        }
        assertTrue(channel.stdout.isClosedForReceive)
    }

    @Test
    fun `duplicate local EOF sends only one packet`() = runTest {
        val (channel, conn) = createChannel()

        channel.sendEof()
        channel.sendEof()

        coVerify(exactly = 1) { conn.sendChannelEof(1) }
    }
}
