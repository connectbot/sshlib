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

import org.connectbot.sshlib.SshException
import org.junit.Test
import java.math.BigInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Curve25519KeyExchangeTest {
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
    fun `public key derivation from RFC 7748 test vector`() {
        val provider = X25519ProviderFactory.provider
        val publicKey = provider.publicFromPrivate(alicePrivate)
        assertContentEquals(alicePublic, publicKey)
    }

    @Test
    fun `shared secret computation with RFC 7748 test vectors`() {
        val provider = X25519ProviderFactory.provider
        val secret = provider.computeSharedSecret(alicePrivate, bobPublic)
        assertContentEquals(expectedSharedSecret, secret)
    }

    @Test
    fun `generateClientKeys returns 32-byte public key`() {
        val kex = Curve25519KeyExchange()
        val publicKey = kex.generateClientKeys()
        assertEquals(32, publicKey.size)
    }

    @Test
    fun `computeSharedSecret returns wire-encoded mpint`() {
        val aliceKex = Curve25519KeyExchange(X25519ProviderFactory.provider, alicePrivate)
        aliceKex.generateClientKeys()
        val encoded = aliceKex.computeSharedSecret(bobPublic)
        val expectedMpint = encodeMpint(BigInteger(1, expectedSharedSecret).toByteArray())
        assertContentEquals(expectedMpint, encoded)
    }

    @Test
    fun `shared secret roundtrip between two parties`() {
        val aliceKex = Curve25519KeyExchange()
        val bobKex = Curve25519KeyExchange()

        val alicePub = aliceKex.generateClientKeys()
        val bobPub = bobKex.generateClientKeys()

        val aliceSecret = aliceKex.computeSharedSecret(bobPub)
        val bobSecret = bobKex.computeSharedSecret(alicePub)

        assertContentEquals(aliceSecret, bobSecret)
    }

    @Test
    fun `rejects server key with wrong size`() {
        val kex = Curve25519KeyExchange()
        kex.generateClientKeys()
        assertFailsWith<SshException> {
            kex.computeSharedSecret(ByteArray(16))
        }
    }

    @Test
    fun `rejects all-zero shared secret`() {
        val allZeroPublic = ByteArray(32)
        val kex = Curve25519KeyExchange()
        kex.generateClientKeys()
        assertFailsWith<SshException> {
            kex.computeSharedSecret(allZeroPublic)
        }
    }

    @Test
    fun `hash algorithm is SHA-256`() {
        val kex = Curve25519KeyExchange()
        assertEquals("SHA-256", kex.hashAlgorithm)
    }

    private fun hexToBytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
