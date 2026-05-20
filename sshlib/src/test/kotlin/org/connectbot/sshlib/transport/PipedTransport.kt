/*
 * ConnectBot SSH Library
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

import kotlinx.coroutines.channels.Channel
import org.connectbot.sshlib.transport.TransportException

class PipedTransport private constructor(
    private val inbound: Channel<ByteArray>,
    private val outbound: Channel<ByteArray>,
) : Transport {

    companion object {
        fun create(): Pair<PipedTransport, PipedTransport> {
            val aToB = Channel<ByteArray>(Channel.UNLIMITED)
            val bToA = Channel<ByteArray>(Channel.UNLIMITED)
            return PipedTransport(bToA, aToB) to PipedTransport(aToB, bToA)
        }
    }

    private val readBuffer = ArrayDeque<Byte>()

    @Volatile
    private var closed = false

    override suspend fun read(count: Int): ByteArray {
        while (readBuffer.size < count) {
            val chunk = try {
                inbound.receive()
            } catch (_: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
                throw TransportException("Transport closed")
            }
            readBuffer.addAll(chunk.toList())
        }
        return ByteArray(count) { readBuffer.removeFirst() }
    }

    override suspend fun write(data: ByteArray) {
        if (closed) throw TransportException("Transport closed")
        outbound.send(data)
    }

    override suspend fun close() {
        closed = true
        outbound.close()
    }

    override val isConnected: Boolean get() = !closed
}
