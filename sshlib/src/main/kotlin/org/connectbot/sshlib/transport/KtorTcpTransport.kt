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
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Collections

/**
 * TCP socket transport implementation using Ktor.
 *
 * This provides a lightweight TCP transport layer using Ktor's networking
 * APIs, suitable for use on Android and JVM platforms.
 *
 * @param host Remote host to connect to
 * @param port Remote port (default 22 for SSH)
 */
class KtorTcpTransport internal constructor(
    private val host: String,
    private val port: Int,
    private val addressResolver: AddressResolver,
    private val socketFactory: TcpSocketFactory? = null,
    private val ipVersion: IpVersion = IpVersion.AUTO,
) : Transport {

    constructor(host: String, port: Int = 22, ipVersion: IpVersion = IpVersion.AUTO) : this(
        host,
        port,
        DefaultAddressResolver(),
        null,
        ipVersion
    )

    private var socket: TransportSocket? = null
    private var readChannel: ByteReadChannel? = null
    private var writeChannel: ByteWriteChannel? = null
    private var selectorManager: SelectorManager? = null

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
            // Initialize selector manager if we don't have a provided factory
            val factory = if (socketFactory == null) {
                val mgr = SelectorManager(Dispatchers.IO)
                selectorManager = mgr
                KtorTcpSocketFactory(mgr)
            } else {
                socketFactory
            }

            val allAddresses = addressResolver.resolve(host)

            if (allAddresses.isEmpty()) {
                throw TransportException("Could not resolve host: $host")
            }

            val addresses = when (ipVersion) {
                IpVersion.IPV4_ONLY -> {
                    val filtered = allAddresses.filterIsInstance<Inet4Address>()
                    if (filtered.isEmpty()) {
                        throw TransportException("No IPv4 addresses found for host: $host")
                    }
                    filtered
                }

                IpVersion.IPV6_ONLY -> {
                    val filtered = allAddresses.filterIsInstance<Inet6Address>()
                    if (filtered.isEmpty()) {
                        throw TransportException("No IPv6 addresses found for host: $host")
                    }
                    filtered
                }

                IpVersion.AUTO -> {
                    // Happy Eyeballs (RFC 8305): interleave IPv6 and IPv4
                    val ipv6 = allAddresses.filterIsInstance<Inet6Address>()
                    val ipv4 = allAddresses.filterIsInstance<Inet4Address>()
                    val other = allAddresses.filter { it !is Inet4Address && it !is Inet6Address }

                    val sorted = mutableListOf<InetAddress>()
                    var v6Index = 0
                    var v4Index = 0
                    while (v6Index < ipv6.size || v4Index < ipv4.size) {
                        if (v6Index < ipv6.size) sorted.add(ipv6[v6Index++])
                        if (v4Index < ipv4.size) sorted.add(ipv4[v4Index++])
                    }
                    sorted.addAll(other)
                    sorted
                }
            }

            socket = connectHappyEyeballs(factory, addresses)

            readChannel = socket!!.openReadChannel()
            writeChannel = socket!!.openWriteChannel(autoFlush = false)
        } catch (e: TransportException) {
            selectorManager?.close()
            selectorManager = null
            throw e
        } catch (e: Exception) {
            selectorManager?.close()
            selectorManager = null
            throw TransportException("Failed to connect to $host:$port", e)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun connectHappyEyeballs(
        factory: TcpSocketFactory,
        addresses: List<InetAddress>,
    ): TransportSocket = supervisorScope {
        val resultChannel = Channel<TransportSocket>(capacity = 1)
        val failures = Collections.synchronizedList(mutableListOf<Throwable>())
        val attempts = Collections.synchronizedList(mutableListOf<Job>())

        val launcherJob = launch {
            for ((index, address) in addresses.withIndex()) {
                if (!resultChannel.isEmpty) break

                // Happy Eyeballs delay (e.g. 250ms) before starting next attempt
                if (index > 0) {
                    delay(250)
                    if (!resultChannel.isEmpty) break
                }

                val job = launch {
                    try {
                        val s = factory.connect(address, port)

                        if (resultChannel.trySend(s).isSuccess) {
                            // Winner
                        } else {
                            // Lost the race
                            s.close()
                        }
                    } catch (e: Throwable) {
                        failures.add(e)
                    }
                }
                attempts.add(job)
            }
        }

        // Watcher to close channel if all fail
        launch {
            launcherJob.join()
            // Wait for all initiated attempts to finish
            attempts.toList().joinAll()
            resultChannel.close()
        }

        try {
            val winner = resultChannel.receive()
            launcherJob.cancel()
            attempts.forEach { it.cancel() }
            return@supervisorScope winner
        } catch (e: ClosedReceiveChannelException) {
            val failureMsg = if (failures.isNotEmpty()) {
                failures.joinToString("; ") { it.message ?: it.toString() }
            } else {
                "Unknown error"
            }
            throw TransportException("Failed to connect to $host:$port. Tried ${addresses.size} addresses. Errors: $failureMsg")
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
            writeChannel?.flushAndClose()
            readChannel?.cancel()
            socket?.close()
            selectorManager?.close()
        } finally {
            writeChannel = null
            readChannel = null
            socket = null
            selectorManager = null
        }
    }
}
