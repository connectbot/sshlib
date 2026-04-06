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
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AgentChannelTest {
    private val handler = mockk<AgentProtocolHandler>()
    private val connection = mockk<SshConnection>(relaxed = true)
    private val localChannel = 100
    private val remoteChannel = 200
    private val maxPacketSize = 1024
    private val initialWindowSize = 4096L

    private val agentChannel = AgentChannel(
        handler,
        connection,
        localChannel,
        remoteChannel,
        maxPacketSize,
        initialWindowSize
    )

    @Test
    fun `handleData calls handler and sends response`() = runTest {
        val request = byteArrayOf(1, 2, 3)
        val response = byteArrayOf(4, 5, 6)

        coEvery { handler.handleRequest(request) } returns response

        agentChannel.handleData(request)

        coVerify { handler.handleRequest(request) }
        coVerify { connection.sendChannelData(remoteChannel, response) }
    }

    @Test
    fun `onWindowAdjust increases window and allows more data to be sent`() = runTest {
        val smallWindowChannel = AgentChannel(
            handler,
            connection,
            localChannel,
            remoteChannel,
            maxPacketSize,
            0L
        )

        val request = byteArrayOf(1, 2, 3)
        val response = byteArrayOf(4, 5, 6)
        coEvery { handler.handleRequest(request) } returns response

        // This would suspend if we don't adjust window
        val job = launch {
            smallWindowChannel.handleData(request)
        }

        smallWindowChannel.onWindowAdjust(10L)
        job.join()

        coVerify { connection.sendChannelData(remoteChannel, response) }
    }

    @Test
    fun `onClose sends CHANNEL_CLOSE and closes channel`() = runTest {
        assertTrue(agentChannel.isOpen)

        agentChannel.onClose()

        assertFalse(agentChannel.isOpen)
        coVerify { connection.sendChannelClose(remoteChannel) }
    }

    @Test
    fun `onClose only sends CHANNEL_CLOSE once`() = runTest {
        agentChannel.onClose()
        agentChannel.onClose()

        coVerify(exactly = 1) { connection.sendChannelClose(remoteChannel) }
    }

    @Test
    fun `handleData does nothing if channel is closed`() = runTest {
        agentChannel.onClose()
        agentChannel.handleData(byteArrayOf(1, 2, 3))

        coVerify(exactly = 0) { handler.handleRequest(any()) }
    }

    @Test
    fun `onEof does not throw`() {
        agentChannel.onEof()
    }
}
