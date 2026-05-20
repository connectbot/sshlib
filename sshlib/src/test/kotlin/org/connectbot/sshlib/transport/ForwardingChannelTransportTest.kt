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

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.client.ForwardingChannel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class ForwardingChannelTransportTest {

    private fun createTransport(): Pair<ForwardingChannelTransport, ForwardingChannel> {
        val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)
        val fwdChannel = mockk<ForwardingChannel>(relaxed = true) {
            every { incomingData } returns dataChannel
            every { isOpen } returns true
        }
        val transport = ForwardingChannelTransport(fwdChannel)
        return transport to fwdChannel
    }

    @Test
    fun `read returns exact number of bytes from single chunk`() = runTest {
        val (transport, fwdChannel) = createTransport()
        (fwdChannel.incomingData as Channel<ByteArray>).send("hello world".toByteArray())

        val result = transport.read(5)

        assertEquals("hello", String(result))
    }

    @Test
    fun `read assembles bytes across multiple chunks`() = runTest {
        val (transport, fwdChannel) = createTransport()
        val dataChannel = fwdChannel.incomingData as Channel<ByteArray>
        dataChannel.send("hel".toByteArray())
        dataChannel.send("lo".toByteArray())

        val result = transport.read(5)

        assertEquals("hello", String(result))
    }

    @Test
    fun `read preserves leftover bytes for next read`() = runTest {
        val (transport, fwdChannel) = createTransport()
        (fwdChannel.incomingData as Channel<ByteArray>).send("hello world".toByteArray())

        val first = transport.read(5)
        val second = transport.read(6)

        assertEquals("hello", String(first))
        assertEquals(" world", String(second))
    }

    @Test
    fun `read handles many small chunks`() = runTest {
        val (transport, fwdChannel) = createTransport()
        val dataChannel = fwdChannel.incomingData as Channel<ByteArray>
        for (b in "abcdefghij".toByteArray()) {
            dataChannel.send(byteArrayOf(b))
        }

        val result = transport.read(10)

        assertEquals("abcdefghij", String(result))
    }

    @Test
    fun `read throws TransportException when channel closes mid-read`() = runTest {
        val (transport, fwdChannel) = createTransport()
        val dataChannel = fwdChannel.incomingData as Channel<ByteArray>
        dataChannel.send("hi".toByteArray())
        dataChannel.close()

        try {
            transport.read(5)
            fail("Expected TransportException")
        } catch (e: TransportException) {
            assertTrue(e.message!!.contains("closed"))
        }
    }

    @Test
    fun `write delegates to ForwardingChannel sendData`() = runTest {
        val (transport, fwdChannel) = createTransport()
        val data = "test data".toByteArray()

        transport.write(data)

        coVerify { fwdChannel.sendData(data) }
    }

    @Test
    fun `close closes the ForwardingChannel`() = runTest {
        val (transport, fwdChannel) = createTransport()

        transport.close()

        coVerify { fwdChannel.close() }
    }

    @Test
    fun `isConnected reflects ForwardingChannel isOpen`() {
        val fwdChannel = mockk<ForwardingChannel>(relaxed = true) {
            every { incomingData } returns Channel(Channel.UNLIMITED)
        }
        val transport = ForwardingChannelTransport(fwdChannel)

        every { fwdChannel.isOpen } returns true
        assertTrue(transport.isConnected)

        every { fwdChannel.isOpen } returns false
        assertFalse(transport.isConnected)
    }

    @Test
    fun `write throws TransportException after close`() = runTest {
        val fwdChannel = mockk<ForwardingChannel>(relaxed = true) {
            every { incomingData } returns Channel(Channel.UNLIMITED)
            every { isOpen } returns true
        }
        val transport = ForwardingChannelTransport(fwdChannel)

        every { fwdChannel.isOpen } returns false
        coEvery { fwdChannel.sendData(any()) } throws
            kotlinx.coroutines.channels.ClosedSendChannelException("closed")

        transport.close()

        try {
            transport.write("data".toByteArray())
            fail("Expected TransportException")
        } catch (e: TransportException) {
            // expected
        }
    }
}
