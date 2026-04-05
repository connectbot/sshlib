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

package org.connectbot.sshlib.blocking

import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.transport.ByteArrayTransport
import org.connectbot.sshlib.transport.Transport
import org.connectbot.sshlib.transport.TransportException
import org.connectbot.sshlib.transport.TransportFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

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
            "Expected message to contain '$cause' but was '${ex.message}'"
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
