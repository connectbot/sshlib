/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportException
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(ExperimentalCoroutinesApi::class)
class SshConnectionCloseTest {

    @Test
    fun `concurrent close closes transport once`() = runTest {
        val transport = RecordingTransport(suspendClose = true)
        val connection = connection(transport, StandardTestDispatcher(testScheduler))

        val first = async { connection.close() }
        transport.closeStarted.await()
        val second = async { connection.close() }
        yield()

        transport.allowClose.complete(Unit)
        first.await()
        second.await()

        assertEquals(1, transport.closeCalls)
    }

    @Test
    fun `write after close fails without reaching transport`() = runTest {
        val transport = RecordingTransport()
        val connection = connection(transport, StandardTestDispatcher(testScheduler))

        connection.close()

        assertFailsWith<TransportException> {
            connection.sendChannelClose(recipientChannel = 0)
        }
        assertEquals(0, transport.writeCalls)
    }

    private fun connection(transport: Transport, dispatcher: CoroutineDispatcher) = SshConnection(
        transport = transport,
        hostKeyVerifier = object : HostKeyVerifier {
            override suspend fun verify(key: org.connectbot.sshlib.PublicKey): Boolean = true
        },
        coroutineDispatcher = dispatcher,
    )

    private class RecordingTransport(
        private val suspendClose: Boolean = false,
    ) : Transport {
        val closeStarted = CompletableDeferred<Unit>()
        val allowClose = CompletableDeferred<Unit>()
        var closeCalls = 0
        var writeCalls = 0

        override val isConnected: Boolean
            get() = closeCalls == 0

        override suspend fun read(count: Int): ByteArray = throw UnsupportedOperationException()

        override suspend fun write(data: ByteArray) {
            writeCalls++
        }

        override suspend fun close() {
            closeCalls++
            closeStarted.complete(Unit)
            if (suspendClose) allowClose.await()
        }
    }
}
