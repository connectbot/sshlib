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

package org.connectbot.sshlib

import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.transport.TransportFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class SshClientTest {
    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private fun clientWithHost(host: String): SshClient {
        val config = SshClientConfig {
            this.host = host
            this.hostKeyVerifier = acceptAllVerifier
        }
        return SshClient(config)
    }

    private val mockKeyboardInteractiveCallback = object : KeyboardInteractiveCallback {
        override suspend fun onInfoRequest(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
            respond: suspend (responses: List<String>) -> Unit,
        ) {
            respond(emptyList())
        }
    }

    private val mockAuthHandler = object : AuthHandler {
        override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()
        override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null
        override suspend fun onKeyboardInteractivePrompt(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
        ): List<String>? = emptyList()
        override suspend fun onPasswordNeeded(): String? = null
    }

    @Test
    fun `connect returns TransportError when factory fails`() = runTest {
        val config = SshClientConfig {
            this.transportFactory = TransportFactory { throw Exception("fail") }
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        val result = client.connect()
        assertIs<ConnectResult.TransportError>(result)
    }

    @Test
    fun `openSession returns null when not connected`() = runTest {
        val client = clientWithHost("host")
        val session = client.openSession()
        assertNull(session)
    }

    @Test
    fun `authenticatePassword returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticatePassword("user", "pass")
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticateKeyboardInteractive returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticateKeyboardInteractive("user", mockKeyboardInteractiveCallback)
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticatePublicKey returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticatePublicKey("user", "keydata")
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `authenticate returns Error when not connected`() = runTest {
        val client = clientWithHost("host")
        val result = client.authenticate("user", mockAuthHandler)
        assertIs<AuthResult.Error>(result)
    }

    @Test
    fun `isPrivateKeyEncrypted handles invalid key data gracefully`() {
        val client = clientWithHost("host")
        // This should not throw but return false or log error
        client.isPrivateKeyEncrypted("invalid key data")
    }

    @Test
    fun `connectionInfo is null before connect`() {
        val client = clientWithHost("host")
        assertNull(client.connectionInfo)
    }

    @Test
    fun `SshClientConfig has default rekey thresholds`() {
        val config = SshClientConfig {
            host = "example.com"
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            }
        }
        assertEquals(3_600_000L, config.rekeyIntervalMs)
        assertEquals(1_073_741_824L, config.rekeyBytesLimit)
    }

    @Test
    fun `SshClientConfig custom rekey thresholds are applied`() {
        val config = SshClientConfig {
            host = "example.com"
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            }
            rekeyIntervalMs = 60_000L
            rekeyBytesLimit = 1024L
        }
        assertEquals(60_000L, config.rekeyIntervalMs)
        assertEquals(1024L, config.rekeyBytesLimit)
    }

    @Test
    fun `SshClientConfig rejects port 0`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "example.com"
                port = 0
                hostKeyVerifier = acceptAllVerifier
            }
        }
    }

    @Test
    fun `SshClientConfig rejects port 65536`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "example.com"
                port = 65536
                hostKeyVerifier = acceptAllVerifier
            }
        }
    }

    @Test
    fun `SshClientConfig accepts port 1`() {
        SshClientConfig {
            host = "example.com"
            port = 1
            hostKeyVerifier = acceptAllVerifier
        }
    }

    @Test
    fun `SshClientConfig accepts port 65535`() {
        SshClientConfig {
            host = "example.com"
            port = 65535
            hostKeyVerifier = acceptAllVerifier
        }
    }

    @Test
    fun `SshClientConfig rejects blank host`() {
        assertFailsWith<IllegalArgumentException> {
            SshClientConfig {
                host = "  "
                hostKeyVerifier = acceptAllVerifier
            }
        }
    }
}
