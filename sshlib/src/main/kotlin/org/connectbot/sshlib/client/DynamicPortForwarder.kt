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

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.network.sockets.toJavaAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.connectbot.sshlib.PortForwarder
import org.connectbot.sshlib.Socks5Authenticator
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress

internal class DynamicPortForwarder(
    private val scope: CoroutineScope,
    private val connection: SshConnection,
    private val socks5Handler: Socks5Handler,
    private val serverSocket: ServerSocket,
    override val boundHost: String,
    override val boundPort: Int,
) : PortForwarder {
    companion object {
        private val logger = LoggerFactory.getLogger(DynamicPortForwarder::class.java)

        suspend fun create(
            scope: CoroutineScope,
            connection: SshConnection,
            bindAddress: InetSocketAddress,
            authenticator: Socks5Authenticator? = null,
        ): DynamicPortForwarder {
            val selectorManager = SelectorManager(Dispatchers.IO)
            val serverSocket = aSocket(selectorManager).tcp().bind(bindAddress.hostString, bindAddress.port)
            val actualAddress = serverSocket.localAddress.toJavaAddress() as java.net.InetSocketAddress

            val handler = Socks5Handler(authenticator)
            val forwarder = DynamicPortForwarder(
                scope,
                connection,
                handler,
                serverSocket,
                actualAddress.hostString,
                actualAddress.port,
            )
            forwarder.startAcceptLoop()
            return forwarder
        }
    }

    private var acceptJob: Job? = null
    private val dataForwarders = mutableListOf<DataForwarder>()
    private var _isActive = true

    override val isActive: Boolean get() = _isActive

    private fun startAcceptLoop() {
        acceptJob = scope.launch {
            try {
                while (isActive) {
                    val socket = serverSocket.accept()
                    launch { handleConnection(socket) }
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
                // Normal shutdown
            } catch (e: Exception) {
                logger.debug("Accept loop ended: ${e.message}")
            }
        }
    }

    private suspend fun handleConnection(socket: Socket) {
        val readChannel = socket.openReadChannel()
        val writeChannel = socket.openWriteChannel(autoFlush = false)

        val request = try {
            socks5Handler.handleHandshake(readChannel, writeChannel)
        } catch (e: Exception) {
            logger.debug("SOCKS5 handshake failed: ${e.message}")
            socket.close()
            return
        }

        if (request == null) {
            logger.debug("SOCKS5 handshake returned no connect request")
            socket.close()
            return
        }

        val remoteAddr = socket.remoteAddress.toJavaAddress() as? java.net.InetSocketAddress
        val originAddr = remoteAddr?.hostString ?: "127.0.0.1"
        val originPort = remoteAddr?.port ?: 0

        logger.debug("SOCKS5 CONNECT to ${request.host}:${request.port}")

        val sshChannel = connection.openDirectTcpipChannel(
            request.host,
            request.port,
            originAddr,
            originPort,
        )

        if (sshChannel == null) {
            logger.warn("Failed to open direct-tcpip channel for ${request.host}:${request.port}")
            socket.close()
            return
        }

        val forwarder = DataForwarder(scope, sshChannel, readChannel, writeChannel)
        synchronized(dataForwarders) { dataForwarders.add(forwarder) }
        forwarder.start()
    }

    override suspend fun stop() {
        if (!_isActive) return
        _isActive = false

        acceptJob?.cancelAndJoin()
        synchronized(dataForwarders) {
            dataForwarders.toList()
        }.forEach { it.stop() }

        try {
            serverSocket.close()
        } catch (_: Exception) {}
    }
}
