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

    private val baseBlob = byteArrayOf(1, 2, 3)
    private val otherBlob = byteArrayOf(4, 5, 6)

    @Test
    fun `AgentIdentity equality works correctly`() {
        val key1 = AgentIdentity(publicKeyBlob = baseBlob, comment = "test-key")
        val key2 = AgentIdentity(publicKeyBlob = baseBlob.clone(), comment = "test-key")
        val key3 = AgentIdentity(publicKeyBlob = byteArrayOf(1, 2, 4), comment = "test-key")

        assertEquals(key1, key2)
        assertNotEquals(key1, key3)
        assertEquals(key1.hashCode(), key2.hashCode())
    }

    @Test
    fun `AgentIdentity differs when publicKeyBlob differs`() {
        val a = AgentIdentity(publicKeyBlob = baseBlob, comment = "key")
        val b = AgentIdentity(publicKeyBlob = otherBlob, comment = "key")
        assertNotEquals(a, b)
    }

    @Test
    fun `AgentIdentity differs when comment differs`() {
        val a = AgentIdentity(publicKeyBlob = baseBlob, comment = "key-a")
        val b = AgentIdentity(publicKeyBlob = baseBlob.clone(), comment = "key-b")
        assertNotEquals(a, b)
    }

    @Test
    fun `AgentIdentity differs when destinationConstraints differs`() {
        val a = AgentIdentity(publicKeyBlob = baseBlob, comment = "key", destinationConstraints = null)
        val b = AgentIdentity(publicKeyBlob = baseBlob.clone(), comment = "key", destinationConstraints = emptyList())
        assertNotEquals(a, b)
    }

    @Test
    fun `AgentIdentity self-equality`() {
        val a = AgentIdentity(publicKeyBlob = baseBlob, comment = "key")
        assertEquals(a, a)
    }

    @Test
    fun `AgentIdentity not equal to different type`() {
        val a = AgentIdentity(publicKeyBlob = baseBlob, comment = "key")
        assertNotEquals(a, "not an identity")
    }

    @Test
    fun `AgentIdentity hashCode differs for different blobs`() {
        val a = AgentIdentity(publicKeyBlob = byteArrayOf(1), comment = "key")
        val b = AgentIdentity(publicKeyBlob = byteArrayOf(2), comment = "key")
        assertNotEquals(a.hashCode(), b.hashCode())
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

    private fun baseContext(
        publicKeyBlob: ByteArray = byteArrayOf(1, 2, 3),
        dataToSign: ByteArray = byteArrayOf(4, 5, 6),
        flags: Int = 0,
        sessionId: ByteArray = byteArrayOf(7, 8, 9),
        serverHostKey: ByteArray = byteArrayOf(10, 11, 12),
        isBound: Boolean = true,
    ) = AgentSigningContext(publicKeyBlob, dataToSign, flags, sessionId, serverHostKey, isBound)

    @Test
    fun `AgentSigningContext differs when publicKeyBlob differs`() {
        assertNotEquals(baseContext(publicKeyBlob = byteArrayOf(1, 2, 3)), baseContext(publicKeyBlob = byteArrayOf(9, 9, 9)))
    }

    @Test
    fun `AgentSigningContext differs when dataToSign differs`() {
        assertNotEquals(baseContext(dataToSign = byteArrayOf(1)), baseContext(dataToSign = byteArrayOf(2)))
    }

    @Test
    fun `AgentSigningContext differs when flags differs`() {
        assertNotEquals(baseContext(flags = 0), baseContext(flags = 2))
    }

    @Test
    fun `AgentSigningContext differs when sessionId differs`() {
        assertNotEquals(baseContext(sessionId = byteArrayOf(1)), baseContext(sessionId = byteArrayOf(2)))
    }

    @Test
    fun `AgentSigningContext differs when serverHostKey differs`() {
        assertNotEquals(baseContext(serverHostKey = byteArrayOf(1)), baseContext(serverHostKey = byteArrayOf(2)))
    }

    @Test
    fun `AgentSigningContext differs when isBound differs`() {
        assertNotEquals(baseContext(isBound = true), baseContext(isBound = false))
    }

    @Test
    fun `AgentSigningContext self-equality`() {
        val ctx = baseContext()
        assertEquals(ctx, ctx)
    }

    @Test
    fun `AgentSigningContext not equal to different type`() {
        assertNotEquals(baseContext(), "not a context")
    }

    @Test
    fun `AgentSigningContext hashCode differs when fields differ`() {
        assertNotEquals(baseContext(flags = 1).hashCode(), baseContext(flags = 2).hashCode())
        assertNotEquals(baseContext(isBound = true).hashCode(), baseContext(isBound = false).hashCode())
    }

    @Test
    fun `AgentKeySpec equals and hashCode`() {
        val spec1 = AgentKeySpec(keyBlob = byteArrayOf(1, 2, 3), isCa = true)
        val spec2 = AgentKeySpec(keyBlob = byteArrayOf(1, 2, 3), isCa = true)
        val specDiffBlob = AgentKeySpec(keyBlob = byteArrayOf(9, 9, 9), isCa = true)
        val specDiffCa = AgentKeySpec(keyBlob = byteArrayOf(1, 2, 3), isCa = false)

        assertEquals(spec1, spec2)
        assertEquals(spec1.hashCode(), spec2.hashCode())
        assertNotEquals(spec1, specDiffBlob)
        assertNotEquals(spec1, specDiffCa)
    }

    @Test
    fun `AgentKeySpec differs when keyBlob differs`() {
        val a = AgentKeySpec(keyBlob = byteArrayOf(1), isCa = false)
        val b = AgentKeySpec(keyBlob = byteArrayOf(2), isCa = false)
        assertNotEquals(a, b)
    }

    @Test
    fun `AgentKeySpec differs when isCa differs`() {
        val a = AgentKeySpec(keyBlob = byteArrayOf(1, 2, 3), isCa = true)
        val b = AgentKeySpec(keyBlob = byteArrayOf(1, 2, 3), isCa = false)
        assertNotEquals(a, b)
    }

    @Test
    fun `AgentKeySpec self-equality`() {
        val spec = AgentKeySpec(keyBlob = byteArrayOf(1, 2), isCa = false)
        assertEquals(spec, spec)
    }

    @Test
    fun `AgentKeySpec not equal to different type`() {
        assertNotEquals(AgentKeySpec(byteArrayOf(1), false), "string")
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
