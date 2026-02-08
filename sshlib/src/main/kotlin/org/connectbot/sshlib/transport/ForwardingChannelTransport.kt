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

package org.connectbot.sshlib.transport

import org.connectbot.sshlib.client.ForwardingChannel

/**
 * [Transport] backed by a [ForwardingChannel].
 *
 * Bridges the chunk-oriented [ForwardingChannel.incomingData] to the
 * exact-count [Transport.read] contract using an internal buffer.
 * Used to run a second SSH connection over a direct-tcpip channel
 * (jump host / ProxyJump) without transiting the kernel network stack.
 */
internal class ForwardingChannelTransport(
    private val channel: ForwardingChannel
) : Transport {

    private var buffer = ByteArray(0)
    private var bufferOffset = 0

    override val isConnected: Boolean
        get() = channel.isOpen

    override suspend fun read(count: Int): ByteArray {
        val result = ByteArray(count)
        var filled = 0

        while (filled < count) {
            if (bufferOffset < buffer.size) {
                val available = buffer.size - bufferOffset
                val toCopy = minOf(available, count - filled)
                System.arraycopy(buffer, bufferOffset, result, filled, toCopy)
                bufferOffset += toCopy
                filled += toCopy
            } else {
                val chunk = channel.incomingData.receiveCatching().getOrNull()
                    ?: throw TransportException("Channel closed before $count bytes could be read")
                buffer = chunk
                bufferOffset = 0
            }
        }

        return result
    }

    override suspend fun write(data: ByteArray) {
        try {
            channel.sendData(data)
        } catch (e: Exception) {
            throw TransportException("Write failed: ${e.message}", e)
        }
    }

    override suspend fun close() {
        channel.close()
    }
}
