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
import org.connectbot.sshlib.SshException
import org.slf4j.LoggerFactory

internal class AgentChannel(
    private val handler: AgentProtocolHandler,
    private val connection: SshConnection,
    private val localChannelNumber: Int,
    private var remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(AgentChannel::class.java)
        private const val MAX_WINDOW_SIZE = 0xFFFFFFFFL
    }

    private var _isOpen = true
    private var closeSent = false

    @Volatile private var remoteWindowSize: Long = remoteWindowSizeInitial
    private val windowAvailable = Channel<Unit>(Channel.CONFLATED)

    val isOpen: Boolean get() = _isOpen

    suspend fun handleData(data: ByteArray) {
        if (!_isOpen) {
            logger.warn("Received data on closed agent channel")
            return
        }

        logger.debug("Agent channel received ${data.size} bytes")

        val response = handler.handleRequest(data)

        logger.debug("Sending agent response (${response.size} bytes)")
        sendData(response)
    }

    fun onWindowAdjust(bytesToAdd: Long) {
        if (bytesToAdd <= 0) {
            throw SshException("Invalid window adjust: bytesToAdd must be positive, got $bytesToAdd")
        }
        if (remoteWindowSize + bytesToAdd > MAX_WINDOW_SIZE) {
            throw SshException("Channel window overflow: current=$remoteWindowSize, adding=$bytesToAdd exceeds max $MAX_WINDOW_SIZE")
        }
        remoteWindowSize += bytesToAdd
        logger.debug("Agent channel window adjust +$bytesToAdd, remote window now $remoteWindowSize")
        if (remoteWindowSize > 0) {
            windowAvailable.trySend(Unit)
        }
    }

    fun onEof() {
        logger.debug("Agent channel received EOF")
    }

    suspend fun onClose() {
        logger.debug("Agent channel closed")
        if (!closeSent) {
            closeSent = true
            try {
                connection.sendChannelClose(remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE reply", e)
            }
        }
        _isOpen = false
        windowAvailable.close()
    }

    private suspend fun sendData(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            while (remoteWindowSize <= 0) {
                windowAvailable.receive()
            }
            val chunkSize = minOf(
                data.size - offset,
                remoteWindowSize.toInt(),
                maxPacketSize,
            )
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            connection.sendChannelData(remoteChannelNumber, chunk)
            remoteWindowSize -= chunkSize
            offset += chunkSize
        }
    }
}
