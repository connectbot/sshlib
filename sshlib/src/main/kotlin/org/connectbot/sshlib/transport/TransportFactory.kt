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

/**
 * Controls which IP address families are used for TCP connections.
 */
enum class IpVersion {
    /** Use Happy Eyeballs (RFC 8305) to race IPv6 and IPv4. */
    AUTO,

    /** Connect only over IPv4. */
    IPV4_ONLY,

    /** Connect only over IPv6. */
    IPV6_ONLY,
}

/**
 * Factory for creating transport connections.
 *
 * Implement this interface to provide custom transport implementations
 * for SSH connections. The library provides [KtorTcpTransportFactory]
 * as a default TCP implementation.
 *
 * Example custom implementation:
 * ```kotlin
 * class MyTransportFactory : TransportFactory {
 *     override suspend fun create(): Transport {
 *         return MyCustomTransport()
 *     }
 * }
 * ```
 */
fun interface TransportFactory {
    /**
     * Create and connect a new transport instance.
     *
     * @return A connected [Transport] ready for reading and writing
     * @throws TransportException if connection fails
     */
    suspend fun create(): Transport
}

/**
 * Factory that creates [KtorTcpTransport] instances for TCP connections.
 *
 * This is the default transport factory used when connecting to SSH servers
 * over TCP/IP.
 *
 * @param host The hostname or IP address to connect to
 * @param port The port number (default 22)
 * @param ipVersion Which address families to use (default [IpVersion.AUTO])
 */
class KtorTcpTransportFactory(
    private val host: String,
    private val port: Int = 22,
    private val ipVersion: IpVersion = IpVersion.AUTO,
) : TransportFactory {
    override suspend fun create(): Transport {
        val transport = KtorTcpTransport(host, port, ipVersion = ipVersion)
        transport.connect()
        return transport
    }
}
