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

import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory

internal class AgentChannel(
    private val handler: AgentProtocolHandler,
    private val connection: SshConnection,
    private val localChannelNumber: Int,
    private var remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    private var remoteWindowSize: Long
) {
    companion object {
        private val logger = LoggerFactory.getLogger(AgentChannel::class.java)
    }

    private var isOpen = true
    private var closeSent = false

    suspend fun handleData(data: ByteArray) {
        if (!isOpen) {
            logger.warn("Received data on closed agent channel")
            return
        }

        logger.debug("Agent channel received ${data.size} bytes")

        val response = handler.handleRequest(data)

        logger.debug("Sending agent response (${response.size} bytes)")
        sendData(response)
    }

    fun onWindowAdjust(bytesToAdd: Long) {
        remoteWindowSize += bytesToAdd
        logger.debug("Agent channel window adjust +$bytesToAdd, remote window now $remoteWindowSize")
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
        isOpen = false
    }

    private suspend fun sendData(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            while (remoteWindowSize <= 0) {
                kotlinx.coroutines.delay(10)
            }
            val chunkSize = minOf(
                data.size - offset,
                remoteWindowSize.toInt(),
                maxPacketSize
            )
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            connection.sendChannelData(remoteChannelNumber, chunk)
            remoteWindowSize -= chunkSize
            offset += chunkSize
        }
    }
}
