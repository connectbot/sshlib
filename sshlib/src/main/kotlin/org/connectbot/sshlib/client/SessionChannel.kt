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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.protocol.ByteString
import org.connectbot.sshlib.protocol.ChannelRequestExec
import org.connectbot.sshlib.protocol.ChannelRequestPtyReq
import org.connectbot.sshlib.protocol.ChannelRequestShell
import org.connectbot.sshlib.protocol.ChannelRequestSubsystem
import org.connectbot.sshlib.protocol.ChannelRequestWindowChange
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

class SessionChannel internal constructor(
    private val connection: SshConnection,
    private val connectionScope: CoroutineScope,
    override val localChannelNumber: Int,
    private var _remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long = 0,
    private val initialWindowSize: Int = 64 * 1024,
    private val canSendChaff: Boolean = false,
    private val obscureKeystrokeTimingIntervalMs: Long = 20L,
    private val obfuscatorClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    private val obfuscatorRandom: Random = Random.Default,
) : SshSession {
    companion object {
        private val logger = LoggerFactory.getLogger(SessionChannel::class.java)
    }

    private var _isOpen = true
    private var closeSent = false
    private val window = LocalChannelWindow(initialWindowSize, remoteInitial = remoteWindowSizeInitial)
    private val windowAvailable = Channel<Unit>(Channel.CONFLATED)

    private val _stdout = Channel<ByteArray>(Channel.UNLIMITED)
    private val _stderr = Channel<ByteArray>(Channel.UNLIMITED)
    private val _extendedData = Channel<Pair<Int, ByteArray>>(Channel.UNLIMITED)

    override val isOpen: Boolean get() = _isOpen
    override val remoteChannelNumber: Int get() = _remoteChannelNumber
    override val stdout: ReceiveChannel<ByteArray> get() = _stdout
    override val stderr: ReceiveChannel<ByteArray> get() = _stderr

    private var ptyGranted = false
    private var obfuscator: KeystrokeObfuscator? = null
    private val obfuscatorMutex = Mutex()
    private var chaffJob: Job? = null
    private val pendingObfuscatedWrites = AtomicInteger(0)
    private val obfuscatedWritesIdle = Channel<Unit>(Channel.CONFLATED)

    /** Called by tests that need to simulate PTY being granted without a real channel request. */
    internal fun markPtyGranted() {
        ptyGranted = true
    }

    private val obfuscationActive: Boolean
        get() = ptyGranted && canSendChaff && obscureKeystrokeTimingIntervalMs > 0

    internal suspend fun onData(data: ByteArray) {
        val adjust = window.consumeLocal(data.size)
        _stdout.trySend(data)
        if (adjust > 0) {
            connection.sendWindowAdjust(_remoteChannelNumber, adjust)
        }
    }

    internal suspend fun onExtendedData(dataType: Int, data: ByteArray) {
        val adjust = window.consumeLocal(data.size)
        _extendedData.trySend(dataType to data)
        if (dataType == 1) {
            _stderr.trySend(data)
        }
        if (adjust > 0) {
            connection.sendWindowAdjust(_remoteChannelNumber, adjust)
        }
    }

    internal fun onWindowAdjust(bytesToAdd: Long) {
        window.adjustRemote(bytesToAdd)
        logger.debug("Window adjust +$bytesToAdd, remote window now ${window.remoteRemaining}")
        if (window.remoteRemaining > 0) {
            windowAvailable.trySend(Unit)
        }
    }

    internal fun onEof() {
        logger.debug("Received EOF on channel $localChannelNumber")
        _stdout.close()
        _stderr.close()
        _extendedData.close()
    }

    internal suspend fun onClose() {
        logger.debug("Received CLOSE on channel $localChannelNumber")
        obfuscatorMutex.withLock {
            obfuscator?.stop()
        }
        chaffJob?.cancel()
        if (!closeSent) {
            closeSent = true
            try {
                connection.sendChannelClose(_remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE reply", e)
            }
        }
        _isOpen = false
        _stdout.close()
        _stderr.close()
        _extendedData.close()
        windowAvailable.close()
    }

    override suspend fun write(data: ByteArray) {
        if (obfuscationActive) {
            writeObfuscated(data)
        } else {
            writeDirect(data)
        }
    }

    private suspend fun writeDirect(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            while (window.remoteRemaining <= 0) {
                windowAvailable.receive()
            }
            val chunkSize = minOf(
                data.size - offset,
                window.remoteRemaining.toInt(),
                maxPacketSize,
            )
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            connection.sendChannelData(_remoteChannelNumber, chunk)
            window.consumeRemote(chunkSize)
            offset += chunkSize
        }
    }

    private suspend fun writeObfuscated(data: ByteArray) {
        pendingObfuscatedWrites.incrementAndGet()
        try {
            val (obs, justStarted) = obfuscatorMutex.withLock {
                val current = obfuscator ?: KeystrokeObfuscator(
                    obscureKeystrokeTimingIntervalMs,
                    clockMs = obfuscatorClockMs,
                    random = obfuscatorRandom,
                ).also {
                    obfuscator = it
                }
                current to current.recordKeystroke()
            }
            startChaffLoopIfNeeded(obs)

            if (!justStarted) {
                val delayMs = obfuscatorMutex.withLock {
                    obs.delayUntilNextSendMs()
                }
                if (delayMs > 0) {
                    delay(delayMs)
                }
                obfuscatorMutex.withLock {
                    obs.advanceInterval()
                }
            }

            writeDirect(data)
        } finally {
            if (pendingObfuscatedWrites.decrementAndGet() == 0) {
                obfuscatedWritesIdle.trySend(Unit)
            }
        }
    }

    private fun startChaffLoopIfNeeded(obs: KeystrokeObfuscator) {
        if (chaffJob?.isActive == true) return
        chaffJob = connectionScope.launch {
            while (obfuscatorMutex.withLock { obs.isActive() }) {
                val delayMs = obfuscatorMutex.withLock {
                    obs.delayUntilNextSendMs()
                }
                if (delayMs > 0) {
                    delay(delayMs)
                }
                val shouldSendChaff = obfuscatorMutex.withLock {
                    if (!obs.isActive()) {
                        false
                    } else if (pendingObfuscatedWrites.get() > 0) {
                        null
                    } else {
                        obs.advanceInterval()
                        true
                    }
                }
                when (shouldSendChaff) {
                    true -> connection.sendChaff()
                    false -> break
                    null -> obfuscatedWritesIdle.receiveCatching()
                }
            }
        }
    }

    override suspend fun read(): ByteArray? = _stdout.receiveCatching().getOrNull()

    override suspend fun readExtended(): Pair<Int, ByteArray>? = _extendedData.receiveCatching().getOrNull()

    override suspend fun sendEof() {
        connection.sendChannelEof(_remoteChannelNumber)
    }

    override suspend fun resizeTerminal(
        widthChars: Int,
        heightRows: Int,
        widthPixels: Int,
        heightPixels: Int,
    ): Boolean {
        logger.debug("Resizing terminal: ${widthChars}x$heightRows")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "window-change",
            wantReply = false,
        ) { msg ->
            val windowChange = ChannelRequestWindowChange()
            windowChange.setTerminalWidth(widthChars.toLong())
            windowChange.setTerminalHeight(heightRows.toLong())
            windowChange.setTerminalWidthPixels(widthPixels.toLong())
            windowChange.setTerminalHeightPixels(heightPixels.toLong())
            windowChange._check()
            msg.setRequestSpecificFields(windowChange)
        }
    }

    override suspend fun requestPty(
        terminalType: String,
        widthChars: Int,
        heightRows: Int,
        widthPixels: Int,
        heightPixels: Int,
        terminalModes: ByteArray,
    ): Boolean {
        logger.debug("Requesting PTY: $terminalType ${widthChars}x$heightRows")
        val granted = connection.sendChannelRequest(
            _remoteChannelNumber,
            "pty-req",
            wantReply = true,
        ) { msg ->
            val ptyReq = ChannelRequestPtyReq()

            val termBytes = ByteString()
            termBytes.setLenData(terminalType.length.toLong())
            termBytes.setData(terminalType.toByteArray(Charsets.US_ASCII))
            termBytes._check()
            ptyReq.setTerm(termBytes)

            ptyReq.setTerminalWidth(widthChars.toLong())
            ptyReq.setTerminalHeight(heightRows.toLong())
            ptyReq.setTerminalWidthPixels(widthPixels.toLong())
            ptyReq.setTerminalHeightPixels(heightPixels.toLong())

            val modeString = ByteString()
            modeString.setLenData(terminalModes.size.toLong())
            modeString.setData(terminalModes)
            modeString._check()
            ptyReq.setTerminalModes(modeString)

            ptyReq._check()
            msg.setRequestSpecificFields(ptyReq)
        }
        if (granted) ptyGranted = true
        return granted
    }

    override suspend fun requestShell(): Boolean {
        logger.debug("Requesting shell on channel $localChannelNumber")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "shell",
            wantReply = true,
        ) { msg ->
            val shellReq = ChannelRequestShell()
            shellReq._check()
            msg.setRequestSpecificFields(shellReq)
        }
    }

    override suspend fun requestExec(command: String): Boolean {
        logger.debug("Requesting exec on channel $localChannelNumber: $command")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "exec",
            wantReply = true,
        ) { msg ->
            val execReq = ChannelRequestExec()
            val cmdString = ByteString()
            cmdString.setLenData(command.toByteArray(Charsets.UTF_8).size.toLong())
            cmdString.setData(command.toByteArray(Charsets.UTF_8))
            cmdString._check()
            execReq.setCommand(cmdString)
            execReq._check()
            msg.setRequestSpecificFields(execReq)
        }
    }

    override suspend fun requestSubsystem(name: String): Boolean {
        logger.debug("Requesting subsystem on channel $localChannelNumber: $name")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "subsystem",
            wantReply = true,
        ) { msg ->
            val subsysReq = ChannelRequestSubsystem()
            val nameString = ByteString()
            nameString.setLenData(name.toByteArray(Charsets.US_ASCII).size.toLong())
            nameString.setData(name.toByteArray(Charsets.US_ASCII))
            nameString._check()
            subsysReq.setSubsystemName(nameString)
            subsysReq._check()
            msg.setRequestSpecificFields(subsysReq)
        }
    }

    override fun close() {
        if (!_isOpen) return

        logger.debug("Closing channel $localChannelNumber")
        obfuscator?.stop()
        chaffJob?.cancel()
        closeSent = true
        _isOpen = false
        _stdout.close()
        _stderr.close()
        _extendedData.close()
        connectionScope.launch {
            try {
                connection.sendChannelClose(_remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE", e)
            }
        }
    }
}
