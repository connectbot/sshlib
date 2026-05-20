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

package org.connectbot.sshlib.client

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readFully
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.Socks5Authenticator
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class Socks5HandlerTest {

    private fun buildSocks5Connect(
        host: String,
        port: Int,
        authMethods: ByteArray = byteArrayOf(0x00),
        useDomain: Boolean = true,
    ): ByteArray {
        val buf = ByteBuffer.allocate(512)

        // Method selection
        buf.put(0x05) // version
        buf.put(authMethods.size.toByte())
        buf.put(authMethods)

        // Connect request
        buf.put(0x05) // version
        buf.put(0x01) // CMD CONNECT
        buf.put(0x00) // RSV

        if (useDomain) {
            buf.put(0x03) // ATYP domain
            val domainBytes = host.toByteArray(Charsets.US_ASCII)
            buf.put(domainBytes.size.toByte())
            buf.put(domainBytes)
        }

        buf.put(((port shr 8) and 0xFF).toByte())
        buf.put((port and 0xFF).toByte())

        buf.flip()
        val bytes = ByteArray(buf.remaining())
        buf.get(bytes)
        return bytes
    }

    private fun buildSocks5ConnectIPv4(
        addr: ByteArray,
        port: Int,
        authMethods: ByteArray = byteArrayOf(0x00),
    ): ByteArray {
        val buf = ByteBuffer.allocate(512)

        // Method selection
        buf.put(0x05)
        buf.put(authMethods.size.toByte())
        buf.put(authMethods)

        // Connect request
        buf.put(0x05) // version
        buf.put(0x01) // CMD CONNECT
        buf.put(0x00) // RSV
        buf.put(0x01) // ATYP IPv4
        buf.put(addr)
        buf.put(((port shr 8) and 0xFF).toByte())
        buf.put((port and 0xFF).toByte())

        buf.flip()
        val bytes = ByteArray(buf.remaining())
        buf.get(bytes)
        return bytes
    }

    private fun buildSocks5ConnectIPv6(
        addr: ByteArray,
        port: Int,
        authMethods: ByteArray = byteArrayOf(0x00),
    ): ByteArray {
        val buf = ByteBuffer.allocate(512)

        // Method selection
        buf.put(0x05)
        buf.put(authMethods.size.toByte())
        buf.put(authMethods)

        // Connect request
        buf.put(0x05) // version
        buf.put(0x01) // CMD CONNECT
        buf.put(0x00) // RSV
        buf.put(0x04) // ATYP IPv6
        buf.put(addr)
        buf.put(((port shr 8) and 0xFF).toByte())
        buf.put((port and 0xFF).toByte())

        buf.flip()
        val bytes = ByteArray(buf.remaining())
        buf.get(bytes)
        return bytes
    }

    private fun buildSocks5WithAuth(
        host: String,
        port: Int,
        username: String,
        password: String,
    ): ByteArray {
        val buf = ByteBuffer.allocate(512)

        // Method selection with username/password auth
        buf.put(0x05) // version
        buf.put(0x01) // 1 method
        buf.put(0x02) // username/password

        // Username/password sub-negotiation (RFC 1929)
        buf.put(0x01) // auth version
        val usernameBytes = username.toByteArray(Charsets.UTF_8)
        buf.put(usernameBytes.size.toByte())
        buf.put(usernameBytes)
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        buf.put(passwordBytes.size.toByte())
        buf.put(passwordBytes)

        // Connect request
        buf.put(0x05) // version
        buf.put(0x01) // CMD CONNECT
        buf.put(0x00) // RSV
        buf.put(0x03) // ATYP domain
        val domainBytes = host.toByteArray(Charsets.US_ASCII)
        buf.put(domainBytes.size.toByte())
        buf.put(domainBytes)
        buf.put(((port shr 8) and 0xFF).toByte())
        buf.put((port and 0xFF).toByte())

        buf.flip()
        val bytes = ByteArray(buf.remaining())
        buf.get(bytes)
        return bytes
    }

    @Test
    fun `domain name connect succeeds`() = runTest {
        val handler = Socks5Handler()
        val input = buildSocks5Connect("example.com", 80)
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNotNull(result)
        assertEquals("example.com", result!!.host)
        assertEquals(80, result.port)
    }

    @Test
    fun `IPv4 connect succeeds`() = runTest {
        val handler = Socks5Handler()
        val input = buildSocks5ConnectIPv4(byteArrayOf(192.toByte(), 168.toByte(), 1, 1), 8080)
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNotNull(result)
        assertEquals("192.168.1.1", result!!.host)
        assertEquals(8080, result.port)
    }

    @Test
    fun `IPv6 connect succeeds`() = runTest {
        val handler = Socks5Handler()
        // ::1 in full form
        val ipv6 = ByteArray(16)
        ipv6[15] = 1
        val input = buildSocks5ConnectIPv6(ipv6, 443)
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNotNull(result)
        assertEquals("0000:0000:0000:0000:0000:0000:0000:0001", result!!.host)
        assertEquals(443, result.port)
    }

    @Test
    fun `wrong SOCKS version returns null`() = runTest {
        val handler = Socks5Handler()
        val input = byteArrayOf(0x04, 0x01, 0x00) // SOCKS4
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNull(result)
    }

    @Test
    fun `username password auth succeeds`() = runTest {
        val authenticator = object : Socks5Authenticator {
            override fun authenticate(username: String, password: String): Boolean = username == "user" && password == "pass"
        }
        val handler = Socks5Handler(authenticator)
        val input = buildSocks5WithAuth("example.com", 80, "user", "pass")
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNotNull(result)
        assertEquals("example.com", result!!.host)
        assertEquals(80, result.port)
    }

    @Test
    fun `username password auth fails`() = runTest {
        val authenticator = object : Socks5Authenticator {
            override fun authenticate(username: String, password: String): Boolean = false
        }
        val handler = Socks5Handler(authenticator)
        val input = buildSocks5WithAuth("example.com", 80, "bad", "creds")
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNull(result)
    }

    @Test
    fun `no acceptable auth method returns null`() = runTest {
        val authenticator = object : Socks5Authenticator {
            override fun authenticate(username: String, password: String): Boolean = true
        }
        val handler = Socks5Handler(authenticator)
        // Only offer NO_AUTH (0x00) but handler requires username/password
        val input = byteArrayOf(0x05, 0x01, 0x00)
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNull(result)
    }

    @Test
    fun `reply contains success byte for valid connect`() = runTest {
        val handler = Socks5Handler()
        val input = buildSocks5Connect("example.com", 80)
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        handler.handleHandshake(readChannel, writeChannel)

        // Read method selection response
        val methodResponse = ByteArray(2)
        writeChannel.readFully(methodResponse, 0, 2)
        assertEquals(0x05.toByte(), methodResponse[0])
        assertEquals(0x00.toByte(), methodResponse[1]) // NO_AUTH selected

        // Read connect reply
        val reply = ByteArray(10) // ver + rep + rsv + atyp + 4 addr + 2 port
        writeChannel.readFully(reply, 0, 10)
        assertEquals(0x05.toByte(), reply[0]) // version
        assertEquals(0x00.toByte(), reply[1]) // success
    }

    @Test
    fun `high port number handled correctly`() = runTest {
        val handler = Socks5Handler()
        val input = buildSocks5Connect("example.com", 65535)
        val readChannel = ByteReadChannel(input)
        val writeChannel = ByteChannel(true)

        val result = handler.handleHandshake(readChannel, writeChannel)

        assertNotNull(result)
        assertEquals(65535, result!!.port)
    }
}
