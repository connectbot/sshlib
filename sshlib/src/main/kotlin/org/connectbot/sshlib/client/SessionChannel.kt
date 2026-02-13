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

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.protocol.ByteString
import org.connectbot.sshlib.protocol.ChannelRequestPtyReq
import org.connectbot.sshlib.protocol.ChannelRequestShell
import org.connectbot.sshlib.protocol.ChannelRequestWindowChange
import org.slf4j.LoggerFactory

class SessionChannel internal constructor(
    private val connection: SshConnection,
    override val localChannelNumber: Int,
    private var _remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    private var remoteWindowSize: Long = 0,
    private val initialWindowSize: Int = 64 * 1024,
) : SshSession {
    companion object {
        private val logger = LoggerFactory.getLogger(SessionChannel::class.java)
        private const val WINDOW_ADJUST_THRESHOLD = 16 * 1024
    }

    private var _isOpen = true
    private var closeSent = false
    private var localWindowSize: Long = initialWindowSize.toLong()

    private val _stdout = Channel<ByteArray>(Channel.UNLIMITED)
    private val _stderr = Channel<ByteArray>(Channel.UNLIMITED)
    private val _extendedData = Channel<Pair<Int, ByteArray>>(Channel.UNLIMITED)

    override val isOpen: Boolean get() = _isOpen
    override val remoteChannelNumber: Int get() = _remoteChannelNumber
    override val stdout: ReceiveChannel<ByteArray> get() = _stdout
    override val stderr: ReceiveChannel<ByteArray> get() = _stderr

    internal fun onData(data: ByteArray) {
        _stdout.trySend(data)
        localWindowSize -= data.size
        if (localWindowSize < WINDOW_ADJUST_THRESHOLD) {
            val adjust = initialWindowSize - localWindowSize.toInt()
            localWindowSize += adjust
            runBlocking {
                connection.sendWindowAdjust(_remoteChannelNumber, adjust)
            }
        }
    }

    internal fun onExtendedData(dataType: Int, data: ByteArray) {
        _extendedData.trySend(dataType to data)
        if (dataType == 1) {
            _stderr.trySend(data)
        }
        localWindowSize -= data.size
        if (localWindowSize < WINDOW_ADJUST_THRESHOLD) {
            val adjust = initialWindowSize - localWindowSize.toInt()
            localWindowSize += adjust
            runBlocking {
                connection.sendWindowAdjust(_remoteChannelNumber, adjust)
            }
        }
    }

    internal fun onWindowAdjust(bytesToAdd: Long) {
        remoteWindowSize += bytesToAdd
        logger.debug("Window adjust +$bytesToAdd, remote window now $remoteWindowSize")
    }

    internal fun onEof() {
        logger.debug("Received EOF on channel $localChannelNumber")
        _stdout.close()
        _stderr.close()
        _extendedData.close()
    }

    internal suspend fun onClose() {
        logger.debug("Received CLOSE on channel $localChannelNumber")
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
    }

    override suspend fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            // Wait for remote window to have space
            while (remoteWindowSize <= 0) {
                kotlinx.coroutines.delay(10)
            }
            val chunkSize = minOf(
                data.size - offset,
                remoteWindowSize.toInt(),
                maxPacketSize
            )
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            connection.sendChannelData(_remoteChannelNumber, chunk)
            remoteWindowSize -= chunkSize
            offset += chunkSize
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
            wantReply = false
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
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "pty-req",
            wantReply = true
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
    }

    override suspend fun requestShell(): Boolean {
        logger.debug("Requesting shell on channel $localChannelNumber")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "shell",
            wantReply = true
        ) { msg ->
            val shellReq = ChannelRequestShell()
            shellReq._check()
            msg.setRequestSpecificFields(shellReq)
        }
    }

    override fun close() {
        if (!_isOpen) return

        logger.debug("Closing channel $localChannelNumber")
        closeSent = true
        runBlocking {
            connection.sendChannelClose(_remoteChannelNumber)
        }
        _isOpen = false
        _stdout.close()
        _stderr.close()
        _extendedData.close()
    }
}
