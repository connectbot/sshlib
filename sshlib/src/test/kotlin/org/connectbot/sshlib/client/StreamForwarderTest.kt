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

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeFully
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StreamForwarderTest {

    private fun createMockChannel(): ForwardingChannel {
        val channel = mockk<ForwardingChannel>(relaxed = true)
        every { channel.isOpen } returns true
        return channel
    }

    @Test
    fun `start forwards data from read channel to ssh`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        coEvery { connection.openDirectTcpipChannel("example.com", 80, "127.0.0.1", 0) } returns
            ForwardingChannel(connection, 0, 1, 32 * 1024, 256L * 1024)

        val input = ByteChannel(autoFlush = true)
        val output = ByteChannel(autoFlush = true)

        val forwarder = StreamForwarder.create(
            connection,
            input,
            output,
            "example.com",
            80,
        )
        assertNotNull(forwarder)
        assertTrue(forwarder!!.isActive)

        input.writeFully("hello".toByteArray())
        input.flushAndClose()

        delay(200)
        forwarder.stop()
        assertFalse(forwarder.isActive)
    }

    @Test
    fun `create returns null when channel open fails`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        coEvery { connection.openDirectTcpipChannel(any(), any(), any(), any()) } returns null

        val input = ByteChannel(autoFlush = true)
        val output = ByteChannel(autoFlush = true)

        val forwarder = StreamForwarder.create(
            connection,
            input,
            output,
            "example.com",
            80,
        )
        assertNull(forwarder)
    }

    @Test
    fun `stop is idempotent`() = runTest {
        val connection = mockk<SshConnection>(relaxed = true)
        coEvery { connection.openDirectTcpipChannel("example.com", 80, "127.0.0.1", 0) } returns
            ForwardingChannel(connection, 0, 1, 32 * 1024, 256L * 1024)

        val input = ByteChannel(autoFlush = true)
        val output = ByteChannel(autoFlush = true)

        val forwarder = StreamForwarder.create(
            connection,
            input,
            output,
            "example.com",
            80,
        )!!

        forwarder.stop()
        forwarder.stop()
        assertFalse(forwarder.isActive)
    }
}
