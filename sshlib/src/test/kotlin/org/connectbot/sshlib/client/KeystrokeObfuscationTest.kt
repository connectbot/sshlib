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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.crypto.AesCtrCipher
import org.connectbot.sshlib.crypto.HmacSha256
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportException
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class KeystrokeObfuscationTest {

    private data class WireWrite(val timeMs: Long, val size: Int)

    private class RecordingTransport(
        private val currentTimeMs: () -> Long,
    ) : Transport {
        val writes = mutableListOf<WireWrite>()
        private var connected = true

        override suspend fun read(count: Int): ByteArray = throw TransportException("RecordingTransport does not support reads")

        override suspend fun write(data: ByteArray) {
            if (!connected) throw TransportException("Transport closed")
            writes += WireWrite(currentTimeMs(), data.size)
        }

        override suspend fun close() {
            connected = false
        }

        override val isConnected: Boolean
            get() = connected
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun createObfuscatingChannel(
        connection: SshConnection,
        canSendChaff: Boolean,
        intervalMs: Long,
        scope: CoroutineScope,
        obfuscatorClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
        obfuscatorRandom: Random = Random.Default,
    ): SessionChannel = SessionChannel(
        connection = connection,
        connectionScope = scope,
        localChannelNumber = 0,
        _remoteChannelNumber = 1,
        maxPacketSize = 32 * 1024,
        remoteWindowSizeInitial = 64 * 1024L,
        initialWindowSize = 64 * 1024,
        canSendChaff = canSendChaff,
        obscureKeystrokeTimingIntervalMs = intervalMs,
        obfuscatorClockMs = obfuscatorClockMs,
        obfuscatorRandom = obfuscatorRandom,
    )

    @Test
    fun `write without PTY does not send chaff`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), any(), any(), any()) } returns true

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )

        // No PTY requested — write directly
        channel.write("a".toByteArray())
        advanceUntilIdle()

        coVerify(exactly = 0) { conn.sendChaff() }
        coVerify(exactly = 1) { conn.sendChannelData(any(), any()) }
    }

    @Test
    fun `write with PTY but canSendChaff false does not send chaff`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), any(), any(), any()) } returns true

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = false,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())
        advanceUntilIdle()

        coVerify(exactly = 0) { conn.sendChaff() }
        coVerify(exactly = 1) { conn.sendChannelData(any(), any()) }
    }

    @Test
    fun `write with PTY and intervalMs zero does not send chaff`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), any(), any(), any()) } returns true

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 0L,
            scope = CoroutineScope(dispatcher),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())
        advanceUntilIdle()

        coVerify(exactly = 0) { conn.sendChaff() }
        coVerify(exactly = 1) { conn.sendChannelData(any(), any()) }
    }

    @Test
    fun `first obfuscated write is sent immediately`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        val sendTimes = mutableListOf<Long>()
        coEvery { conn.sendChannelData(any(), any()) } coAnswers {
            sendTimes += testScheduler.currentTime
            Unit
        }

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())

        assertEquals(listOf(0L), sendTimes)
    }

    @Test
    fun `write with PTY canSendChaff and interval sends chaff during chaff window`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), any(), any(), any()) } returns true

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())
        // Advance past chaff window (CHAFF_MIN_MS=100 + up to CHAFF_RANGE_MS=400 ms)
        testScheduler.advanceTimeBy(600L)
        advanceUntilIdle()

        // At least one chaff packet should have been sent
        coVerify(atLeast = 1) { conn.sendChaff() }
        coVerify(exactly = 1) { conn.sendChannelData(any(), any()) }
    }

    @Test
    fun `chaff restarts for a later typing burst`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        var chaffCount = 0
        coEvery { conn.sendChaff() } coAnswers {
            chaffCount++
            Unit
        }

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())
        testScheduler.advanceTimeBy(600L)
        advanceUntilIdle()
        val firstBurstChaffCount = chaffCount
        assertTrue(firstBurstChaffCount > 0, "Expected chaff during first burst")

        channel.write("b".toByteArray())
        testScheduler.advanceTimeBy(600L)
        advanceUntilIdle()

        assertTrue(chaffCount > firstBurstChaffCount, "Expected chaff to restart for second burst")
    }

    @Test
    fun `encrypted keystroke and chaff packets have same size and twenty millisecond cadence`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val transport = RecordingTransport { testScheduler.currentTime }
        val connection = SshConnection(
            transport = transport,
            hostKeyVerifier = acceptAllVerifier,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )
        connection.serverSupportsPing = true
        enableTestEncryption(connection)

        val channel = createObfuscatingChannel(
            connection,
            canSendChaff = true,
            intervalMs = 20L,
            scope = backgroundScope,
            obfuscatorClockMs = { testScheduler.currentTime },
            obfuscatorRandom = Random(0),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())
        backgroundScope.launch(dispatcher) {
            delay(7)
            channel.write("b".toByteArray())
        }
        testScheduler.advanceTimeBy(140)

        val writes = transport.writes
        assertTrue(writes.size >= 5, "Expected keystrokes plus chaff, got $writes")
        assertEquals(
            setOf(64),
            writes.map { it.size }.toSet(),
            "Single-byte CHANNEL_DATA and chaff PING packets must have identical encrypted wire sizes",
        )

        val intervals = writes.zipWithNext { a, b -> b.timeMs - a.timeMs }
        assertTrue(
            intervals.all { it in 15L..25L },
            "Expected encrypted keystroke/chaff packets roughly 20ms apart, got writes=$writes intervals=$intervals",
        )

        channel.close()
        connection.close()
    }

    @Test
    fun `chaff stops after chaff window expires`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), any(), any(), any()) } returns true
        var chaffCount = 0
        coEvery { conn.sendChaff() } coAnswers {
            chaffCount++
            Unit
        }

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )
        channel.markPtyGranted()

        channel.write("a".toByteArray())
        testScheduler.advanceTimeBy(600L)
        advanceUntilIdle()

        // Record chaff count at this point.
        coVerify(atLeast = 1) { conn.sendChaff() }
        val chaffCountAfterWindow = chaffCount

        // Wait much longer — no more chaff should be sent
        testScheduler.advanceTimeBy(5_000L)
        advanceUntilIdle()

        assertEquals(chaffCountAfterWindow, chaffCount)
    }

    @Test
    fun `requestPty sets ptyGranted on success`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), eq("pty-req"), any(), any()) } returns true

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )

        val result = channel.requestPty("xterm", 80, 24, 0, 0, byteArrayOf())
        assertTrue(result)

        // Now write — should activate obfuscation (chaff will be sent)
        channel.write("a".toByteArray())
        testScheduler.advanceTimeBy(600L)
        advanceUntilIdle()

        coVerify(atLeast = 1) { conn.sendChaff() }
    }

    @Test
    fun `requestPty does not set ptyGranted on failure`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val conn = mockk<SshConnection>(relaxed = true)
        coEvery { conn.sendChannelRequest(any(), eq("pty-req"), any(), any()) } returns false

        val channel = createObfuscatingChannel(
            conn,
            canSendChaff = true,
            intervalMs = 20L,
            scope = CoroutineScope(dispatcher),
        )

        val result = channel.requestPty("xterm", 80, 24, 0, 0, byteArrayOf())
        assertFalse(result)

        channel.write("a".toByteArray())
        advanceUntilIdle()

        coVerify(exactly = 0) { conn.sendChaff() }
    }

    private fun enableTestEncryption(connection: SshConnection) {
        val packetIoField = SshConnection::class.java.getDeclaredField("packetIO")
        packetIoField.isAccessible = true
        val packetIO = packetIoField.get(connection) as PacketIO

        val cipherKey = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it + 0x10).toByte() }
        val macKey = ByteArray(32) { (it + 0x20).toByte() }

        packetIO.enableEncryption(
            clientToServerCipher = AesCtrCipher(cipherKey.copyOf(), iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCtrCipher(cipherKey.copyOf(), iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
        )
    }
}
