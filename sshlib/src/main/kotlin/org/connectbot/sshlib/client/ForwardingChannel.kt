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
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.launch
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.protocol.SshChannelState
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import org.slf4j.LoggerFactory

internal class ForwardingChannel(
    private val connection: SshConnection,
    private val connectionScope: CoroutineScope,
    val localChannelNumber: Int,
    var remoteChannelNumber: Int,
    private val maxPacketSize: Int,
    remoteWindowSizeInitial: Long,
    private val initialWindowSize: Int = 256 * 1024,
    private val lifecycle: SshChannelStateMachine = SshChannelStateMachine(SshChannelState.OPEN),
) {
    companion object {
        private val logger = LoggerFactory.getLogger(ForwardingChannel::class.java)
    }

    private val window = LocalChannelWindow(
        initialWindowSize,
        remoteInitial = remoteWindowSizeInitial,
    )
    private val windowAvailable = Channel<Unit>(Channel.CONFLATED)

    private val incomingIngress = Channel<ByteArray>(Channel.UNLIMITED)
    private val _incomingData = Channel<ByteArray>(Channel.RENDEZVOUS)
    val incomingData: ReceiveChannel<ByteArray> get() = _incomingData
    private val incomingDeliveryJob = connectionScope.launch {
        try {
            for (data in incomingIngress) {
                _incomingData.send(data)
                val adjust = window.releaseLocal(data.size)
                connection.sendWindowAdjust(remoteChannelNumber, adjust)
            }
        } finally {
            _incomingData.close()
        }
    }

    val isOpen: Boolean get() = lifecycle.isOpen

    internal suspend fun onData(data: ByteArray) {
        if (!lifecycle.receiveData()) {
            throw SshException("Received data after EOF or CLOSE on forwarding channel $localChannelNumber")
        }
        window.consumeLocal(data.size)
        if (incomingIngress.trySend(data).isFailure) {
            throw org.connectbot.sshlib.SshException("Received data for a closed forwarding stream")
        }
    }

    internal suspend fun onWindowAdjust(bytesToAdd: Long) {
        if (!lifecycle.receiveWindowAdjust()) {
            throw SshException("Received window adjustment after CLOSE on forwarding channel $localChannelNumber")
        }
        window.adjustRemote(bytesToAdd)
        logger.debug("Forwarding channel window adjust +$bytesToAdd, remote window now ${window.remoteRemaining}")
        if (window.remoteRemaining > 0) {
            windowAvailable.trySend(Unit)
        }
    }

    internal suspend fun onEof() {
        if (!lifecycle.receiveEof()) {
            throw SshException("Received duplicate EOF or EOF after CLOSE on forwarding channel $localChannelNumber")
        }
        logger.debug("Forwarding channel $localChannelNumber received EOF")
        incomingIngress.close()
    }

    internal suspend fun onClose() {
        val replyRequired = lifecycle.state != SshChannelState.CLOSE_SENT
        if (!lifecycle.receiveClose()) {
            throw SshException("Received duplicate CLOSE on forwarding channel $localChannelNumber")
        }
        logger.debug("Forwarding channel $localChannelNumber closed")
        if (replyRequired) {
            try {
                connection.sendChannelClose(remoteChannelNumber)
            } catch (e: Exception) {
                logger.debug("Failed to send CHANNEL_CLOSE reply", e)
            }
        }
        incomingIngress.close()
        incomingDeliveryJob.cancel()
        _incomingData.close()
        windowAvailable.close()
    }

    internal suspend fun onDisconnected() {
        lifecycle.disconnect()
        incomingIngress.close()
        incomingDeliveryJob.cancel()
        _incomingData.close()
        windowAvailable.close()
    }

    internal suspend fun authorizeReceiveRequest(): Boolean = lifecycle.receiveRequest()

    suspend fun sendData(data: ByteArray) {
        if (!lifecycle.sendData()) {
            throw SshException("Cannot send data after EOF or CLOSE on forwarding channel $localChannelNumber")
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

    suspend fun sendEof() {
        if (!lifecycle.sendEof()) return
        connection.sendChannelEof(remoteChannelNumber)
    }

    suspend fun close() {
        if (!lifecycle.sendClose()) return
        incomingIngress.close()
        incomingDeliveryJob.cancel()
        _incomingData.close()
        connection.sendChannelClose(remoteChannelNumber)
    }
}
