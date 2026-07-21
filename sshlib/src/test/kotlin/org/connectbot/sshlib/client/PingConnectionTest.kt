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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PingResult
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.test.assertIs

@OptIn(ExperimentalCoroutinesApi::class)
class PingConnectionTest {

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
    fun `ping returns NotSupported when server does not advertise ping`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertisePing = false
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

            val pingResult = connection.ping()
            assertIs<PingResult.NotSupported>(pingResult)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `ping returns Success when server advertises ping`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
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

            val pingResult = connection.ping()
            assertIs<PingResult.Success>(pingResult)
            assertTrue(pingResult.elapsedNs >= 0)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `opaque chaff pong does not terminate packet processing`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )

        try {
            assertIs<ConnectResult.Success>(connectInBackground(connection, backgroundScope, dispatcher))

            server.sendServerPong("PING!".encodeToByteArray())
            yield()

            assertIs<PingResult.Success>(connection.ping())
        } finally {
            connection.close()
        }
    }

    @Test
    fun `client responds to server ping with pong containing same data`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
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

            val pingData = byteArrayOf(0x01, 0x02, 0x03, 0x04)
            server.sendServerPing(pingData)

            val pongData = withTimeoutOrNull(5_000) { server.awaitPong() }
            assertNotNull(pongData, "Expected pong within timeout")
            assertArrayEquals(pingData, pongData)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `ping queued during rekey completes after rekey finishes`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
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
            while (!connection.isRekeying) {
                yield()
            }

            val pingDeferred = CompletableDeferred<PingResult>()
            backgroundScope.launch(dispatcher) {
                pingDeferred.complete(connection.ping())
            }

            server.rekeyCount.first { it >= 1 }

            val pingResult = withTimeoutOrNull(5_000) { pingDeferred.await() }
            assertNotNull(pingResult, "Ping should resolve after rekey")
            assertIs<PingResult.Success>(pingResult)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `ping fails when connection is closed while pending`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            val pingDeferred = CompletableDeferred<PingResult>()
            backgroundScope.launch(dispatcher) {
                pingDeferred.complete(connection.ping())
            }
            yield()

            connection.close()

            val pingResult = withTimeoutOrNull(5_000) {
                pingDeferred.await()
            }
            assertNotNull(pingResult, "Ping should resolve after connection close")
            assertIs<PingResult.Failure>(pingResult)
        } finally {
            connection.close()
        }
    }
}
