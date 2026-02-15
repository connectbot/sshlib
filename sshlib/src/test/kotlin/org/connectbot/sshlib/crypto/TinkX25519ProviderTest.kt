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

package org.connectbot.sshlib.crypto

import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class TinkX25519ProviderTest {
    private val provider = TinkX25519Provider()

    // RFC 7748 Section 6.1 test vectors
    private val alicePrivate = hexToBytes(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    private val alicePublic = hexToBytes(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    private val bobPrivate = hexToBytes(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    private val bobPublic = hexToBytes(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    private val expectedSharedSecret = hexToBytes(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )

    @Test
    fun `generatePrivateKey returns 32 bytes`() {
        val key = provider.generatePrivateKey()
        assertEquals(32, key.size)
    }

    @Test
    fun `generated keys are unique`() {
        val key1 = provider.generatePrivateKey()
        val key2 = provider.generatePrivateKey()
        assert(!key1.contentEquals(key2)) { "Two generated keys should differ" }
    }

    @Test
    fun `publicFromPrivate matches RFC 7748 Alice test vector`() {
        val publicKey = provider.publicFromPrivate(alicePrivate)
        assertContentEquals(alicePublic, publicKey)
    }

    @Test
    fun `publicFromPrivate matches RFC 7748 Bob test vector`() {
        val publicKey = provider.publicFromPrivate(bobPrivate)
        assertContentEquals(bobPublic, publicKey)
    }

    @Test
    fun `computeSharedSecret matches RFC 7748 test vector`() {
        val secret = provider.computeSharedSecret(alicePrivate, bobPublic)
        assertContentEquals(expectedSharedSecret, secret)
    }

    @Test
    fun `shared secret is symmetric`() {
        val secretAlice = provider.computeSharedSecret(alicePrivate, bobPublic)
        val secretBob = provider.computeSharedSecret(bobPrivate, alicePublic)
        assertContentEquals(secretAlice, secretBob)
    }

    @Test
    fun `generatePrivateKey roundtrip through publicFromPrivate and computeSharedSecret`() {
        val priv1 = provider.generatePrivateKey()
        val pub1 = provider.publicFromPrivate(priv1)
        val priv2 = provider.generatePrivateKey()
        val pub2 = provider.publicFromPrivate(priv2)

        val secret1 = provider.computeSharedSecret(priv1, pub2)
        val secret2 = provider.computeSharedSecret(priv2, pub1)
        assertContentEquals(secret1, secret2)
    }

    private fun hexToBytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
