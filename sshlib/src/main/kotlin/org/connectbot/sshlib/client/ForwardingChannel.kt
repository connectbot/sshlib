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

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import org.slf4j.LoggerFactory

internal class ForwardingChannel(
    private val connection: SshConnection,
    val localChannelNumber: Int,
    var remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long,
    private val initialWindowSize: Int = 256 * 1024,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(ForwardingChannel::class.java)
        private const val WINDOW_ADJUST_THRESHOLD = 64 * 1024
    }

    private var _isOpen = true
    private var closeSent = false
    private val window = LocalChannelWindow(
        initialWindowSize,
        adjustThreshold = WINDOW_ADJUST_THRESHOLD,
        remoteInitial = remoteWindowSizeInitial,
    )
    private val windowAvailable = Channel<Unit>(Channel.CONFLATED)

    private val _incomingData = Channel<ByteArray>(Channel.UNLIMITED)
    val incomingData: ReceiveChannel<ByteArray> get() = _incomingData

    val isOpen: Boolean get() = _isOpen

    internal suspend fun onData(data: ByteArray) {
        val adjust = window.consumeLocal(data.size)
        _incomingData.trySend(data)
        if (adjust > 0) {
            connection.sendWindowAdjust(remoteChannelNumber, adjust)
        }
    }

    internal fun onWindowAdjust(bytesToAdd: Long) {
        window.adjustRemote(bytesToAdd)
        logger.debug("Forwarding channel window adjust +$bytesToAdd, remote window now ${window.remoteRemaining}")
        if (window.remoteRemaining > 0) {
            windowAvailable.trySend(Unit)
        }
    }

    internal fun onEof() {
        logger.debug("Forwarding channel $localChannelNumber received EOF")
        _incomingData.close()
    }

    internal suspend fun onClose() {
        logger.debug("Forwarding channel $localChannelNumber closed")
        if (!closeSent) {
            closeSent = true
            try {
                connection.sendChannelClose(remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE reply", e)
            }
        }
        _isOpen = false
        _incomingData.close()
        windowAvailable.close()
    }

    suspend fun sendData(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            while (window.remoteRemaining <= 0) {
                windowAvailable.receive()
            }
            val chunkSize = window.sendChunkSize(data.size - offset, maxPacketSize)
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            connection.sendChannelData(remoteChannelNumber, chunk)
            window.consumeRemote(chunkSize)
            offset += chunkSize
        }
    }

    suspend fun sendEof() {
        connection.sendChannelEof(remoteChannelNumber)
    }

    suspend fun close() {
        if (!_isOpen) return
        closeSent = true
        _isOpen = false
        _incomingData.close()
        connection.sendChannelClose(remoteChannelNumber)
    }
}
