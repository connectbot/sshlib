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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class AgentProviderTest {

    @Test
    fun `AgentIdentity equality works correctly`() {
        val key1 = AgentIdentity(
            publicKeyBlob = byteArrayOf(1, 2, 3),
            comment = "test-key",
        )
        val key2 = AgentIdentity(
            publicKeyBlob = byteArrayOf(1, 2, 3),
            comment = "test-key",
        )
        val key3 = AgentIdentity(
            publicKeyBlob = byteArrayOf(1, 2, 4),
            comment = "test-key",
        )

        assertEquals(key1, key2)
        assertNotEquals(key1, key3)
        assertEquals(key1.hashCode(), key2.hashCode())
    }

    @Test
    fun `AgentSigningContext equality works correctly`() {
        val context1 = AgentSigningContext(
            publicKeyBlob = byteArrayOf(1, 2, 3),
            dataToSign = byteArrayOf(4, 5, 6),
            flags = 0,
            sessionId = byteArrayOf(7, 8, 9),
            serverHostKey = byteArrayOf(10, 11, 12),
            isBound = true,
        )
        val context2 = AgentSigningContext(
            publicKeyBlob = byteArrayOf(1, 2, 3),
            dataToSign = byteArrayOf(4, 5, 6),
            flags = 0,
            sessionId = byteArrayOf(7, 8, 9),
            serverHostKey = byteArrayOf(10, 11, 12),
            isBound = true,
        )
        val context3 = AgentSigningContext(
            publicKeyBlob = byteArrayOf(1, 2, 3),
            dataToSign = byteArrayOf(4, 5, 6),
            flags = 0,
            sessionId = byteArrayOf(7, 8, 9),
            serverHostKey = byteArrayOf(10, 11, 12),
            isBound = false,
        )

        assertEquals(context1, context2)
        assertNotEquals(context1, context3)
        assertEquals(context1.hashCode(), context2.hashCode())
    }

    @Test
    fun `AgentProvider can be implemented with custom logic`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities(): List<AgentIdentity> = listOf(
                AgentIdentity(
                    publicKeyBlob = byteArrayOf(1, 2, 3),
                    comment = "test-key-1",
                ),
                AgentIdentity(
                    publicKeyBlob = byteArrayOf(4, 5, 6),
                    comment = "test-key-2",
                ),
            )

            override suspend fun signData(context: AgentSigningContext): ByteArray? = if (context.isBound) {
                byteArrayOf(1, 2, 3, 4)
            } else {
                null
            }
        }

        val identities = testProvider.getIdentities()
        assertEquals(2, identities.size)
        assertEquals("test-key-1", identities[0].comment)
        assertEquals("test-key-2", identities[1].comment)

        val boundContext = AgentSigningContext(
            publicKeyBlob = byteArrayOf(1, 2, 3),
            dataToSign = byteArrayOf(4, 5, 6),
            flags = 0,
            sessionId = byteArrayOf(7, 8, 9),
            serverHostKey = byteArrayOf(10, 11, 12),
            isBound = true,
        )
        assertNotNull(testProvider.signData(boundContext))

        val unboundContext = boundContext.copy(isBound = false)
        assertNull(testProvider.signData(unboundContext))
    }

    @Test
    fun `AgentSignatureFlags constants are correct`() {
        assertEquals(0x02, AgentSignatureFlags.RSA_SHA2_256)
        assertEquals(0x04, AgentSignatureFlags.RSA_SHA2_512)
    }
}
