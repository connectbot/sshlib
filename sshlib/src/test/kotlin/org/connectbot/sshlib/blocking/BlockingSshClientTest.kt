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

package org.connectbot.sshlib.blocking

import io.ktor.utils.io.ByteChannel
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PingResult
import org.connectbot.sshlib.PortForwarder
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.SshSession
import org.connectbot.sshlib.StreamForwarder
import org.connectbot.sshlib.transport.ByteArrayTransport
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportException
import org.connectbot.sshlib.transport.TransportFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetSocketAddress

class BlockingSshClientTest {

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun clientWithTransport(factory: suspend () -> Transport): BlockingSshClient {
        val config = SshClientConfig {
            transportFactory = TransportFactory { factory() }
            hostKeyVerifier = acceptAllVerifier
        }
        return BlockingSshClient(config)
    }

    @Test
    fun `connect handles HostKeyRejected`() {
        val client = mockk<SshClient>(relaxed = true)
        val key = mockk<PublicKey>(relaxed = true)
        coEvery { key.type } returns "ssh-rsa"
        coEvery { client.connect() } returns ConnectResult.HostKeyRejected(key)

        val blockingClient = BlockingSshClient(client)
        val ex = assertThrows<SshException> {
            blockingClient.connect()
        }
        assertTrue(ex.message!!.contains("Host key rejected"))
    }

    @Test
    fun `connect handles AlgorithmMismatch`() {
        val client = mockk<SshClient>(relaxed = true)
        coEvery { client.connect() } returns ConnectResult.AlgorithmMismatch("test mismatch")

        val blockingClient = BlockingSshClient(client)
        val ex = assertThrows<SshException> {
            blockingClient.connect()
        }
        assertEquals("test mismatch", ex.message)
    }

    @Test
    fun `connect handles ProtocolError`() {
        val client = mockk<SshClient>(relaxed = true)
        val cause = Exception("proto error")
        coEvery { client.connect() } returns ConnectResult.ProtocolError("proto error msg", cause)

        val blockingClient = BlockingSshClient(client)
        val ex = assertThrows<SshException> {
            blockingClient.connect()
        }
        assertEquals("proto error msg", ex.message)
        assertEquals(cause, ex.cause)
    }

    @Test
    fun `connect returns normally on success`() {
        val client = mockk<SshClient>(relaxed = true)
        coEvery { client.connect() } returns ConnectResult.Success

        BlockingSshClient(client).connect()
    }

    @Test
    fun `connect handles TransportError`() {
        val client = mockk<SshClient>(relaxed = true)
        val cause = Exception("transport")
        coEvery { client.connect() } returns ConnectResult.TransportError(cause)

        val ex = assertThrows<SshException> {
            BlockingSshClient(client).connect()
        }
        assertTrue(ex.message!!.contains("Transport error"))
        assertSame(cause, ex.cause)
    }

    @Test
    fun `authenticatePassword handles Failure`() {
        val client = mockk<SshClient>(relaxed = true)
        coEvery { client.authenticatePassword(any(), any()) } returns AuthResult.Failure(setOf("publickey"))

        val blockingClient = BlockingSshClient(client)
        val ex = assertThrows<SshException> {
            blockingClient.authenticatePassword("user", "pass")
        }
        assertTrue(ex.message!!.contains("Authentication failed"))
        assertTrue(ex.message!!.contains("publickey"))
    }

    @Test
    fun `authenticatePassword handles Error`() {
        val client = mockk<SshClient>(relaxed = true)
        val cause = Exception("auth error")
        coEvery { client.authenticatePassword(any(), any()) } returns AuthResult.Error("auth error msg", cause)

        val blockingClient = BlockingSshClient(client)
        val ex = assertThrows<SshException> {
            blockingClient.authenticatePassword("user", "pass")
        }
        assertEquals("auth error msg", ex.message)
        assertEquals(cause, ex.cause)
    }

    @Test
    fun `authenticate wrappers return normally on success`() {
        val client = mockk<SshClient>(relaxed = true)
        coEvery { client.authenticatePassword(any(), any()) } returns AuthResult.Success
        coEvery { client.authenticate(any(), any()) } returns AuthResult.Success
        coEvery { client.authenticateKeyboardInteractive(any(), any()) } returns AuthResult.Success
        coEvery { client.authenticatePublicKey(any(), any<ByteArray>(), any()) } returns AuthResult.Success
        coEvery { client.authenticatePublicKey(any(), any<String>(), any()) } returns AuthResult.Success
        val blockingClient = BlockingSshClient(client)

        blockingClient.authenticatePassword("user", "pass")
        blockingClient.authenticate("user", mockk())
        blockingClient.authenticateKeyboardInteractive("user", mockk())
        blockingClient.authenticatePublicKey("user", byteArrayOf(1, 2, 3))
        blockingClient.authenticatePublicKey("user", "key")
    }

    @Test
    fun `authenticate wrappers throw on failure and error variants`() {
        val client = mockk<SshClient>(relaxed = true)
        val cause = Exception("auth")
        coEvery { client.authenticate(any(), any()) } returns AuthResult.Failure(setOf("password"))
        coEvery { client.authenticateKeyboardInteractive(any(), any()) } returns AuthResult.Error("keyboard error", cause)
        coEvery { client.authenticatePublicKey(any(), any<ByteArray>(), any()) } returns AuthResult.Failure(setOf("publickey"))
        coEvery { client.authenticatePublicKey(any(), any<String>(), any()) } returns AuthResult.Error("key error", cause)
        val blockingClient = BlockingSshClient(client)

        assertThrows<SshException> { blockingClient.authenticate("user", mockk()) }
        assertThrows<SshException> { blockingClient.authenticateKeyboardInteractive("user", mockk()) }
        assertThrows<SshException> { blockingClient.authenticatePublicKey("user", byteArrayOf(1, 2, 3)) }
        assertThrows<SshException> { blockingClient.authenticatePublicKey("user", "key") }
    }

    @Test
    fun `simple wrappers delegate to async client`() {
        val client = mockk<SshClient>(relaxed = true)
        val session = mockk<SshSession>()
        val sftp = mockk<SftpClient>()
        val localForwarder = mockk<PortForwarder>()
        val remoteForwarder = mockk<PortForwarder>()
        val dynamicForwarder = mockk<PortForwarder>()
        val streamForwarder = mockk<StreamForwarder>()
        val readChannel = ByteChannel(autoFlush = true)
        val writeChannel = ByteChannel(autoFlush = true)
        val bindAddress = InetSocketAddress("127.0.0.1", 0)
        coEvery { client.openSession() } returns session
        coEvery { client.openSftp() } returns SftpResult.Success(sftp)
        coEvery { client.ping() } returns PingResult.NotSupported
        coEvery { client.localPortForward(bindAddress, "remote", 22) } returns localForwarder
        coEvery { client.localPortForward(8022, "remote", 22) } returns localForwarder
        coEvery { client.remotePortForward("0.0.0.0", 0, "localhost", 22) } returns remoteForwarder
        coEvery { client.dynamicPortForward(bindAddress, null) } returns dynamicForwarder
        coEvery { client.dynamicPortForward(1080, null) } returns dynamicForwarder
        coEvery { client.forwardStream(readChannel, writeChannel, "remote", 22, "127.0.0.1", 0) } returns streamForwarder
        val blockingClient = BlockingSshClient(client)

        assertFalse(blockingClient.isAuthenticated)
        assertSame(client.disconnectedFlow, blockingClient.disconnectedFlow)
        assertSame(session, blockingClient.openSession())
        assertSame(sftp, blockingClient.openSftp())
        assertEquals(PingResult.NotSupported, blockingClient.ping())
        assertSame(localForwarder, blockingClient.localPortForward(bindAddress, "remote", 22))
        assertSame(localForwarder, blockingClient.localPortForward(8022, "remote", 22))
        assertSame(remoteForwarder, blockingClient.remotePortForward("0.0.0.0", 0, "localhost", 22))
        assertSame(dynamicForwarder, blockingClient.dynamicPortForward(bindAddress))
        assertSame(dynamicForwarder, blockingClient.dynamicPortForward(1080))
        assertSame(streamForwarder, blockingClient.forwardStream(readChannel, writeChannel, "remote", 22))

        blockingClient.disconnect()
        coVerify { client.disconnect() }
    }

    @Test
    fun `connect throws SshException when transport factory throws`() {
        val cause = TransportException("connection refused")
        val client = clientWithTransport { throw cause }

        val ex = assertThrows<SshException> { client.connect() }
        assertTrue(ex.message!!.contains("Transport error"), "message should contain 'Transport error': ${ex.message}")
        assertEquals(cause, ex.cause)
    }

    @Test
    fun `connect TransportError message uses toString not message to stay non-null`() {
        val cause = RuntimeException("boom")
        val client = clientWithTransport { throw cause }

        val ex = assertThrows<SshException> { client.connect() }
        assertTrue(
            ex.message!!.contains(cause.toString()),
            "Expected message to contain '$cause' but was '${ex.message}'",
        )
    }

    @Test
    fun `connect throws SshException when transport immediately closes without banner`() {
        val client = clientWithTransport { ByteArrayTransport(byteArrayOf()) }

        assertThrows<SshException> { client.connect() }
    }

    @Test
    fun `connect TransportError with null message throwable still produces non-null exception message`() {
        val cause = object : RuntimeException(null as String?) {}
        val client = clientWithTransport { throw cause }

        val ex = assertThrows<SshException> { client.connect() }
        assertTrue(ex.message != null, "SshException message must not be null")
        assertTrue(ex.message!!.startsWith("Transport error: "), "message should start with 'Transport error: ': ${ex.message}")
    }
}
