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

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.isClosed
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.net.InetAddress

/**
 * Resolves hostnames to IP addresses.
 */
interface AddressResolver {
    suspend fun resolve(host: String): List<InetAddress>
}

/**
 * Abstract socket interface to decouple from Ktor's Socket implementation.
 */
interface TransportSocket : Closeable {
    val isClosed: Boolean
    fun openReadChannel(): ByteReadChannel
    fun openWriteChannel(autoFlush: Boolean = false): ByteWriteChannel
}

/**
 * Creates TCP sockets.
 */
interface TcpSocketFactory {
    suspend fun connect(address: InetAddress, port: Int): TransportSocket
}

internal class DefaultAddressResolver : AddressResolver {
    override suspend fun resolve(host: String): List<InetAddress> = withContext(Dispatchers.IO) {
        InetAddress.getAllByName(host).toList()
    }
}

internal class KtorTcpSocketFactory(
    private val selectorManager: SelectorManager,
) : TcpSocketFactory {
    override suspend fun connect(address: InetAddress, port: Int): TransportSocket {
        val socketAddress = InetSocketAddress(address.hostAddress, port)
        val socket = io.ktor.network.sockets.aSocket(selectorManager).tcp().connect(socketAddress)
        return KtorTransportSocket(socket)
    }
}

private class KtorTransportSocket(private val socket: Socket) : TransportSocket {
    override val isClosed: Boolean
        get() = socket.isClosed

    override fun openReadChannel(): ByteReadChannel = socket.openReadChannel()

    override fun openWriteChannel(autoFlush: Boolean): ByteWriteChannel = socket.openWriteChannel(autoFlush)

    override fun close() {
        socket.close()
    }
}
