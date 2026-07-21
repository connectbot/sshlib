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

package org.connectbot.sshlib

import kotlinx.coroutines.test.runTest
import nl.jqno.equalsverifier.EqualsVerifier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import kotlin.test.assertIs

class AgentProviderTest {

    @Test
    fun `AgentIdentity equals and hashCode`() {
        EqualsVerifier.forClass(AgentIdentity::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }

    @Test
    fun `AgentSigningContext equals and hashCode`() {
        EqualsVerifier.forClass(AgentSigningContext::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }

    @Test
    fun `AgentKeySpec equals and hashCode`() {
        EqualsVerifier.forClass(AgentKeySpec::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }

    @Test
    fun `AgentProvider can be implemented with custom logic`() = runTest {
        val testProvider = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(
                listOf(
                    AgentIdentity(
                        publicKeyBlob = byteArrayOf(1, 2, 3),
                        comment = "test-key-1",
                    ),
                    AgentIdentity(
                        publicKeyBlob = byteArrayOf(4, 5, 6),
                        comment = "test-key-2",
                    ),
                ),
            )

            override suspend fun signData(context: AgentSigningContext) = if (context.isBound) {
                AgentResult.Success(byteArrayOf(1, 2, 3, 4))
            } else {
                AgentResult.Success(null)
            }
        }

        val identities = assertIs<AgentResult.Success<List<AgentIdentity>>>(testProvider.getIdentities()).value
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
        assertNotNull(assertIs<AgentResult.Success<ByteArray?>>(testProvider.signData(boundContext)).value)

        val unboundContext = boundContext.copy(isBound = false)
        assertNull(assertIs<AgentResult.Success<ByteArray?>>(testProvider.signData(unboundContext)).value)
    }

    @Test
    fun `AgentSignatureFlags constants are correct`() {
        assertEquals(0x02, AgentSignatureFlags.RSA_SHA2_256)
        assertEquals(0x04, AgentSignatureFlags.RSA_SHA2_512)
    }
}
