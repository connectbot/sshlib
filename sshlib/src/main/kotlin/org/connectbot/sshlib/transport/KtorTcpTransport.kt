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

import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import kotlinx.coroutines.Dispatchers

/**
 * TCP socket transport implementation using Ktor.
 *
 * This provides a lightweight TCP transport layer using Ktor's networking
 * APIs, suitable for use on Android and JVM platforms.
 *
 * @param host Remote host to connect to
 * @param port Remote port (default 22 for SSH)
 */
class KtorTcpTransport(
    private val host: String,
    private val port: Int = 22
) : Transport {
    private var socket: Socket? = null
    private var readChannel: ByteReadChannel? = null
    private var writeChannel: ByteWriteChannel? = null

    override val isConnected: Boolean
        get() = socket?.isClosed == false

    /**
     * Connect to the remote host.
     * Must be called before any read/write operations.
     */
    suspend fun connect() {
        if (socket != null) {
            throw TransportException("Already connected")
        }

        try {
            val selectorManager = SelectorManager(Dispatchers.IO)
            socket = aSocket(selectorManager).tcp().connect(host, port)

            readChannel = socket!!.openReadChannel()
            writeChannel = socket!!.openWriteChannel(autoFlush = false)
        } catch (e: Exception) {
            throw TransportException("Failed to connect to $host:$port", e)
        }
    }

    override suspend fun read(count: Int): ByteArray {
        val channel = readChannel ?: throw TransportException("Not connected")

        try {
            val buffer = ByteArray(count)
            channel.readFully(buffer, 0, count)
            return buffer
        } catch (e: Exception) {
            throw TransportException("Failed to read $count bytes", e)
        }
    }

    override suspend fun write(data: ByteArray) {
        val channel = writeChannel ?: throw TransportException("Not connected")

        try {
            channel.writeFully(data, 0, data.size)
            channel.flush()
        } catch (e: Exception) {
            throw TransportException("Failed to write ${data.size} bytes", e)
        }
    }

    override suspend fun close() {
        try {
            writeChannel?.close()
            readChannel?.cancel()
            socket?.close()
        } finally {
            writeChannel = null
            readChannel = null
            socket = null
        }
    }
}
