/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.test.assertIs

@OptIn(ExperimentalCoroutinesApi::class)
class SshAuthBannerTest {

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private suspend fun connectInBackground(
        connection: SshConnection,
        backgroundScope: CoroutineScope,
        dispatcher: CoroutineDispatcher,
    ): ConnectResult {
        val result = CompletableDeferred<ConnectResult>()
        backgroundScope.launch(dispatcher) { result.complete(connection.connect()) }
        yield()
        return result.await()
    }

    @Test
    fun `onBanner is called when server sends banner during none auth`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        val bannerReceived = CompletableDeferred<String>()
        val handler = object : AuthHandler {
            override suspend fun onAuthMethodsAvailable(methods: Set<String>) {}
            override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = emptyList()
            override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray? = null
            override suspend fun onKeyboardInteractivePrompt(
                name: String,
                instruction: String,
                prompts: List<KeyboardInteractiveCallback.Prompt>,
            ): List<String>? = null
            override suspend fun onPasswordNeeded(): String? = null

            override suspend fun onBanner(message: String) {
                bannerReceived.complete(message)
            }
        }

        try {
            val connectResult = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(connectResult)

            val authJob = backgroundScope.launch(dispatcher) {
                // none auth will fail on fake server usually, but it will wait for the result
                connection.authenticate("user", handler)
            }

            // Wait for server to receive the "none" auth request
            // FakeSshServer doesn't have a way to await auth request easily, but we can just wait a bit or use yield
            yield()

            val bannerText = "Welcome to the test server! Visit https://example.com/auth"
            server.sendUserauthBanner(bannerText)

            // Now fail the auth so authenticate() returns
            server.sendUserauthFailure(setOf("password"), false)

            authJob.join()

            assertEquals(bannerText, bannerReceived.await())
        } finally {
            connection.close()
        }
    }
}
