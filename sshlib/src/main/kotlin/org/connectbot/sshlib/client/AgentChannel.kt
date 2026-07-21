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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

internal class AgentChannel(
    private val handler: AgentProtocolHandler,
    private val connection: SshConnection,
    scope: CoroutineScope,
    private val localChannelNumber: Int,
    private var remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long,
    initialWindowSize: Int = 64 * 1024,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(AgentChannel::class.java)
    }

    private var _isOpen = true
    private var closeSent = false

    private val window = LocalChannelWindow(initialWindowSize, remoteInitial = remoteWindowSizeInitial)
    private val windowAvailable = Channel<Unit>(Channel.CONFLATED)
    private val requests = Channel<ByteArray>(Channel.UNLIMITED)
    private val requestWorker: Job = scope.launch {
        for (data in requests) {
            val response = handler.handleRequest(data)
            connection.sendWindowAdjust(remoteChannelNumber, window.releaseLocal(data.size))

            logger.debug("Sending agent response (${response.size} bytes)")
            sendData(response)
        }
    }

    val isOpen: Boolean get() = _isOpen

    suspend fun handleData(data: ByteArray) {
        if (!_isOpen) {
            logger.warn("Received data on closed agent channel")
            return
        }
        window.consumeLocal(data.size)

        logger.debug("Queueing ${data.size} bytes received on agent channel")
        if (requests.trySend(data).isFailure) {
            window.releaseLocal(data.size)
            logger.warn("Discarding data received while agent channel is closing")
        }
    }

    fun onWindowAdjust(bytesToAdd: Long) {
        window.adjustRemote(bytesToAdd)
        logger.debug("Agent channel window adjust +$bytesToAdd, remote window now ${window.remoteRemaining}")
        if (window.remoteRemaining > 0) {
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
        requests.close()
        requestWorker.cancelAndJoin()
        windowAvailable.close()
    }

    private suspend fun sendData(data: ByteArray) {
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
}
