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

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import java.net.InetAddress
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class KtorTcpTransportTest {

    @Test
    fun `connects successfully with single address`() = runTest {
        val addr = InetAddress.getByName("127.0.0.1")
        val socket = MockSocket()

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(addr)))
        val factory = MockTcpSocketFactory(mapOf(addr to { socket }))

        val transport = KtorTcpTransport("example.com", 22, resolver, factory)
        transport.connect()

        assertTrue(transport.isConnected)
        assertEquals(1, factory.connectionAttempts.size)
        assertEquals(addr, factory.connectionAttempts[0])
    }

    @Test
    fun `happy eyeballs prefers IPv6`() = runTest {
        val ipv4 = InetAddress.getByName("127.0.0.1")
        val ipv6 = InetAddress.getByName("::1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv4, ipv6)))
        val factory = MockTcpSocketFactory(
            mapOf(
                ipv4 to { MockSocket() },
                ipv6 to { MockSocket() }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory)
        transport.connect()

        // Should sort IPv6 first
        assertEquals(ipv6, factory.connectionAttempts[0])
    }

    @Test
    fun `happy eyeballs falls back to second address after delay`() = runTest {
        val ipv6 = InetAddress.getByName("::1") // Will delay
        val ipv4 = InetAddress.getByName("127.0.0.1") // Will succeed immediately

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv6, ipv4)))

        val factory = MockTcpSocketFactory(
            mapOf(
                ipv6 to {
                    delay(500) // Simulates timeout/slow connection
                    MockSocket()
                },
                ipv4 to { MockSocket() }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory)
        transport.connect()

        assertEquals(2, factory.connectionAttempts.size)
        assertEquals(ipv6, factory.connectionAttempts[0])
        assertEquals(ipv4, factory.connectionAttempts[1])
        assertTrue(transport.isConnected)
    }

    @Test
    fun `happy eyeballs wins race`() = runTest {
        val ipv6 = InetAddress.getByName("::1")
        val ipv4 = InetAddress.getByName("127.0.0.1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv6, ipv4)))

        val socket6 = MockSocket()
        val socket4 = MockSocket()

        val factory = MockTcpSocketFactory(
            mapOf(
                ipv6 to {
                    delay(1000)
                    socket6
                },
                ipv4 to {
                    delay(100)
                    socket4
                }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory)
        transport.connect()

        assertEquals(2, factory.connectionAttempts.size)
        assertTrue(transport.isConnected)
    }

    @Test
    fun `throws exception if all attempts fail`() = runTest {
        val addr = InetAddress.getByName("127.0.0.1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(addr)))
        val factory = MockTcpSocketFactory(
            mapOf(
                addr to { throw RuntimeException("Connection refused") }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory)
        assertFailsWith<TransportException> {
            transport.connect()
        }
    }

    @Test
    fun `IPv4_ONLY filters out IPv6 addresses`() = runTest {
        val ipv4 = InetAddress.getByName("127.0.0.1")
        val ipv6 = InetAddress.getByName("::1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv6, ipv4)))
        val factory = MockTcpSocketFactory(
            mapOf(
                ipv4 to { MockSocket() },
                ipv6 to { MockSocket() }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory, IpVersion.IPV4_ONLY)
        transport.connect()

        assertEquals(1, factory.connectionAttempts.size)
        assertEquals(ipv4, factory.connectionAttempts[0])
    }

    @Test
    fun `IPv6_ONLY filters out IPv4 addresses`() = runTest {
        val ipv4 = InetAddress.getByName("127.0.0.1")
        val ipv6 = InetAddress.getByName("::1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv4, ipv6)))
        val factory = MockTcpSocketFactory(
            mapOf(
                ipv4 to { MockSocket() },
                ipv6 to { MockSocket() }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory, IpVersion.IPV6_ONLY)
        transport.connect()

        assertEquals(1, factory.connectionAttempts.size)
        assertEquals(ipv6, factory.connectionAttempts[0])
    }

    @Test
    fun `IPv4_ONLY throws when no IPv4 addresses available`() = runTest {
        val ipv6 = InetAddress.getByName("::1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv6)))
        val factory = MockTcpSocketFactory(mapOf(ipv6 to { MockSocket() }))

        val transport = KtorTcpTransport("example.com", 22, resolver, factory, IpVersion.IPV4_ONLY)
        val ex = assertFailsWith<TransportException> {
            transport.connect()
        }
        assertTrue(ex.message!!.contains("No IPv4"))
    }

    @Test
    fun `IPv6_ONLY throws when no IPv6 addresses available`() = runTest {
        val ipv4 = InetAddress.getByName("127.0.0.1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv4)))
        val factory = MockTcpSocketFactory(mapOf(ipv4 to { MockSocket() }))

        val transport = KtorTcpTransport("example.com", 22, resolver, factory, IpVersion.IPV6_ONLY)
        val ex = assertFailsWith<TransportException> {
            transport.connect()
        }
        assertTrue(ex.message!!.contains("No IPv6"))
    }

    @Test
    fun `IPv4_ONLY connects with multiple IPv4 addresses`() = runTest {
        val ipv4a = InetAddress.getByName("10.0.0.1")
        val ipv4b = InetAddress.getByName("10.0.0.2")
        val ipv6 = InetAddress.getByName("::1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv6, ipv4a, ipv4b)))
        val factory = MockTcpSocketFactory(
            mapOf(
                ipv4a to { throw RuntimeException("refused") },
                ipv4b to { MockSocket() },
                ipv6 to { MockSocket() }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory, IpVersion.IPV4_ONLY)
        transport.connect()

        assertTrue(factory.connectionAttempts.all { it is java.net.Inet4Address })
        assertTrue(transport.isConnected)
    }

    @Test
    fun `AUTO mode interleaves IPv6 and IPv4`() = runTest {
        val ipv4 = InetAddress.getByName("127.0.0.1")
        val ipv6 = InetAddress.getByName("::1")

        val resolver = MockAddressResolver(mapOf("example.com" to listOf(ipv4, ipv6)))
        val factory = MockTcpSocketFactory(
            mapOf(
                ipv4 to { MockSocket() },
                ipv6 to { MockSocket() }
            )
        )

        val transport = KtorTcpTransport("example.com", 22, resolver, factory, IpVersion.AUTO)
        transport.connect()

        assertEquals(ipv6, factory.connectionAttempts[0])
    }
}

class MockAddressResolver(private val hosts: Map<String, List<InetAddress>>) : AddressResolver {
    override suspend fun resolve(host: String): List<InetAddress> = hosts[host] ?: emptyList()
}

class MockTcpSocketFactory(
    private val behaviors: Map<InetAddress, suspend () -> TransportSocket>,
) : TcpSocketFactory {
    val connectionAttempts = mutableListOf<InetAddress>()

    override suspend fun connect(address: InetAddress, port: Int): TransportSocket {
        connectionAttempts.add(address)
        val behavior = behaviors[address] ?: throw RuntimeException("Unexpected address: $address")
        return behavior()
    }
}

class MockSocket : TransportSocket {
    private var closed = false

    override fun close() {
        closed = true
    }

    override val isClosed: Boolean
        get() = closed

    override fun openReadChannel(): ByteReadChannel = ByteChannel(autoFlush = true)
    override fun openWriteChannel(autoFlush: Boolean): ByteWriteChannel = ByteChannel(autoFlush = true)
}
