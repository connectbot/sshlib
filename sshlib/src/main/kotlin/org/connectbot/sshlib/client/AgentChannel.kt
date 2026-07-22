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
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.protocol.SshChannelState
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import org.slf4j.LoggerFactory

internal class AgentChannel(
    private val handler: AgentProtocolHandler,
    private val connection: SshConnection,
    scope: CoroutineScope,
    internal val localChannelNumber: Int,
    private var remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long,
    initialWindowSize: Int = 64 * 1024,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(AgentChannel::class.java)
    }

    private val lifecycle = SshChannelStateMachine(SshChannelState.OPEN)

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

    val isOpen: Boolean get() = lifecycle.isOpen

    suspend fun handleData(data: ByteArray) {
        if (!lifecycle.receiveData()) {
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

    suspend fun onWindowAdjust(bytesToAdd: Long) {
        if (!lifecycle.receiveWindowAdjust()) {
            throw SshException("Received window adjustment after CLOSE on agent channel $localChannelNumber")
        }
        window.adjustRemote(bytesToAdd)
        logger.debug("Agent channel window adjust +$bytesToAdd, remote window now ${window.remoteRemaining}")
        if (window.remoteRemaining > 0) {
            windowAvailable.trySend(Unit)
        }
    }

    suspend fun onEof() {
        if (!lifecycle.receiveEof()) {
            throw SshException("Received duplicate EOF or EOF after CLOSE on agent channel $localChannelNumber")
        }
        logger.debug("Agent channel received EOF")
    }

    suspend fun onClose() {
        val replyRequired = lifecycle.state != SshChannelState.CLOSE_SENT
        if (!lifecycle.receiveClose()) return
        logger.debug("Agent channel closed")
        if (replyRequired) {
            try {
                connection.sendChannelClose(remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE reply", e)
            }
        }
        requests.close()
        requestWorker.cancelAndJoin()
        windowAvailable.close()
    }

    suspend fun onDisconnected() {
        lifecycle.disconnect()
        requests.close()
        requestWorker.cancelAndJoin()
        windowAvailable.close()
    }

    suspend fun authorizeReceiveRequest(): Boolean = lifecycle.receiveRequest()

    private suspend fun sendData(data: ByteArray) {
        if (!lifecycle.sendData()) {
            throw SshException("Cannot send data after EOF or CLOSE on agent channel $localChannelNumber")
        }
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
