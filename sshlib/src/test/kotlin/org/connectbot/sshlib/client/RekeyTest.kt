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

package org.connectbot.sshlib.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import kotlin.test.assertIs

@OptIn(ExperimentalCoroutinesApi::class)
class RekeyTest {

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private suspend fun connectInBackground(
        connection: SshConnection,
        backgroundScope: CoroutineScope,
        dispatcher: CoroutineDispatcher,
    ): ConnectResult {
        val result = CompletableDeferred<ConnectResult>()
        backgroundScope.launch(dispatcher) { result.complete(connection.connect()) }
        yield()
        return result.await()
    }

    @Test
    fun `rekey triggered when byte limit exceeded`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyBytesLimit = 512L,
            rekeyIntervalMs = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            server.sendIgnore()
            server.rekeyCount.first { it >= 1 }

            // Verify connection is still alive after re-key
            server.sendIgnore()
            val disconnectCause = withTimeoutOrNull(250) { connection.disconnectedFlow.first() }
            assertNull(disconnectCause)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `rekey triggered after interval elapses`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyIntervalMs = 3_600_000L,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            assertEquals(0, server.rekeyCount.value)

            advanceTimeBy(3_600_001L)

            server.sendIgnore()
            server.rekeyCount.first { it >= 1 }

            assertEquals(1, server.rekeyCount.value)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `server-initiated rekey is handled correctly`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            server.initiateRekey()
            server.rekeyCount.first { it >= 1 }

            assertEquals(1, server.rekeyCount.value)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `packets received during rekey are not dropped`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            server.sendIgnore()
            server.initiateRekey()
            server.sendIgnore()
            server.rekeyCount.first { it >= 1 }

            assertEquals(1, server.rekeyCount.value)

            // Packet processing should continue after re-key with no disconnect.
            server.sendIgnore()
            val disconnectCause = withTimeoutOrNull(250) { connection.disconnectedFlow.first() }
            assertNull(disconnectCause)
        } finally {
            connection.close()
        }
    }
}
