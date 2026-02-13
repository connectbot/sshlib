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
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionChannelTest {

    private fun createChannel(
        connection: SshConnection = mockk(relaxed = true),
    ): Pair<SessionChannel, SshConnection> {
        val channel = SessionChannel(
            connection = connection,
            localChannelNumber = 0,
            _remoteChannelNumber = 1,
            maxPacketSize = 32 * 1024,
            remoteWindowSize = 64 * 1024L
        )
        return channel to connection
    }

    @Test
    fun `resizeTerminal sends window-change request with correct dimensions`() = runTest {
        val requestTypeSlot = slot<String>()
        val wantReplySlot = slot<Boolean>()
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery {
            conn.sendChannelRequest(any(), capture(requestTypeSlot), capture(wantReplySlot), any())
        } returns true

        val (channel, _) = createChannel(conn)

        val result = channel.resizeTerminal(
            widthChars = 120,
            heightRows = 40,
            widthPixels = 960,
            heightPixels = 640
        )

        assertTrue(result)
        assertEquals("window-change", requestTypeSlot.captured)
        assertFalse(wantReplySlot.captured)
    }

    @Test
    fun `resizeTerminal returns false when request fails`() = runTest {
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), any(), any(), any()) } returns false

        val (channel, _) = createChannel(conn)

        val result = channel.resizeTerminal(
            widthChars = 80,
            heightRows = 24,
            widthPixels = 0,
            heightPixels = 0
        )

        assertFalse(result)
    }

    @Test
    fun `resizeTerminal sends to correct remote channel`() = runTest {
        val channelSlot = slot<Int>()
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery {
            conn.sendChannelRequest(capture(channelSlot), any(), any(), any())
        } returns true

        val (channel, _) = createChannel(conn)

        channel.resizeTerminal(80, 24, 0, 0)

        assertEquals(1, channelSlot.captured)
    }
}
