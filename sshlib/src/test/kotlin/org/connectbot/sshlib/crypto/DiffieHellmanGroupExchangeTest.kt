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

package org.connectbot.sshlib.crypto

import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import javax.crypto.KeyAgreement
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.DHPublicKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DiffieHellmanGroupExchangeTest {

    // A tiny 16-bit prime — far below the min=2048 requested by the client
    private val tinyPrime = BigInteger("65537")

    @Test
    fun `setGroup rejects p smaller than min bits`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        assertFailsWith<SshException> {
            gex.setGroup(tinyPrime, DhGroups.GENERATOR)
        }
    }

    @Test
    fun `setGroup rejects p larger than max bits`() {
        // Construct a number just over 8192 bits
        val tooBig = BigInteger.ONE.shiftLeft(8193)
        val gex = DiffieHellmanGroupExchange("SHA-256")
        assertFailsWith<SshException> {
            gex.setGroup(tooBig, DhGroups.GENERATOR)
        }
    }

    @Test
    fun `setGroup rejects g equal to 1`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        assertFailsWith<SshException> {
            gex.setGroup(DhGroups.GROUP14_P, BigInteger.ONE)
        }
    }

    @Test
    fun `setGroup rejects g equal to 0`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        assertFailsWith<SshException> {
            gex.setGroup(DhGroups.GROUP14_P, BigInteger.ZERO)
        }
    }

    @Test
    fun `setGroup rejects g greater than or equal to p minus 1`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        assertFailsWith<SshException> {
            gex.setGroup(DhGroups.GROUP14_P, DhGroups.GROUP14_P - BigInteger.ONE)
        }
    }

    @Test
    fun `setGroup rejects even p`() {
        val evenP = DhGroups.GROUP14_P.subtract(BigInteger.ONE) // make it even
        val gex = DiffieHellmanGroupExchange("SHA-256")
        assertFailsWith<SshException> {
            gex.setGroup(evenP, DhGroups.GENERATOR)
        }
    }

    @Test
    fun `setGroup rejects odd composite modulus`() {
        val composite = BigInteger.ONE.shiftLeft(2047).add(BigInteger.ONE).multiply(BigInteger.valueOf(3))
        val gex = DiffieHellmanGroupExchange("SHA-256")

        assertFailsWith<SshException> {
            gex.setGroup(composite, DhGroups.GENERATOR)
        }
    }

    @Test
    fun `setGroup accepts valid group 14 parameters`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(DhGroups.GROUP14_P, DhGroups.GENERATOR)
        // Should not throw; verify we can generate keys
        val e = gex.generateClientKeys()
        assertTrue(e.isNotEmpty())
    }

    @Test
    fun `setGroup accepts valid group 16 parameters`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(DhGroups.GROUP16_P, DhGroups.GENERATOR)
        val e = gex.generateClientKeys()
        assertTrue(e.isNotEmpty())
    }

    @Test
    fun `generateClientKeys throws if group not set`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")

        assertFailsWith<SshException> {
            gex.generateClientKeys()
        }
    }

    @Test
    fun `shared secret agreement using group 14 prime`() {
        val p = DhGroups.GROUP14_P
        val g = DhGroups.GENERATOR

        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(p, g)
        val e = gex.generateClientKeys()

        // Simulate server using JCA DH
        val serverKpg = KeyPairGenerator.getInstance("DH")
        serverKpg.initialize(DHParameterSpec(p, g))
        val serverKp = serverKpg.generateKeyPair()
        val serverPub = serverKp.public as DHPublicKey
        val f = serverPub.y.toByteArray()

        val clientSecret = gex.computeSharedSecret(f)

        // Server computes shared secret from client's e
        val serverAgreement = KeyAgreement.getInstance("DH")
        serverAgreement.init(serverKp.private)

        val clientPubKeySpec = DHPublicKeySpec(BigInteger(1, e), p, g)
        val clientPubKey = KeyFactory.getInstance("DH")
            .generatePublic(clientPubKeySpec)
        serverAgreement.doPhase(clientPubKey, true)
        val serverRawSecret = serverAgreement.generateSecret()

        val serverSecret = encodeMpint(BigInteger(1, serverRawSecret).toByteArray())

        assertContentEquals(serverSecret, clientSecret)
    }

    @Test
    fun `failed server public value discards ephemeral private exponent`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(DhGroups.GROUP14_P, DhGroups.GENERATOR)
        gex.generateClientKeys()

        assertFailsWith<SshException> { gex.computeSharedSecret(BigInteger.ONE.toByteArray()) }
        assertFailsWith<SshException> { gex.computeSharedSecret(BigInteger.TWO.toByteArray()) }
    }

    @Test
    fun `validated group cache remains bounded`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        repeat(20) { index ->
            val composite = BigInteger.ONE.shiftLeft(2047)
                .add(BigInteger.valueOf((index * 2L) + 1L))
                .multiply(BigInteger.valueOf(3))
            assertFailsWith<SshException> { gex.setGroup(composite, DhGroups.GENERATOR) }
        }

        assertTrue(DiffieHellmanGroupExchange.cachedGroupValidationCount() <= 16)
    }

    @Test
    fun `exchange hash includes min n max p g`() {
        val p = DhGroups.GROUP14_P
        val g = DhGroups.GENERATOR

        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(p, g)

        val standardDh = DiffieHellman("SHA-256", p, g)

        val vc = "SSH-2.0-Client".toByteArray()
        val vs = "SSH-2.0-Server".toByteArray()
        val ic = ByteArray(16) { it.toByte() }
        val is_ = ByteArray(16) { (it + 16).toByte() }
        val ks = ByteArray(32) { (it + 32).toByte() }
        val e = ByteArray(32) { (it + 64).toByte() }
        val f = ByteArray(32) { (it + 96).toByte() }
        val k = ByteArray(32) { (it + 128).toByte() }

        val gexHash = gex.computeExchangeHash(vc, vs, ic, is_, ks, e, f, k)
        val standardHash = standardDh.computeExchangeHash(vc, vs, ic, is_, ks, e, f, k)

        assertFalse(gexHash.contentEquals(standardHash))
    }

    @Test
    fun `exchange hash is deterministic`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(DhGroups.GROUP14_P, DhGroups.GENERATOR)

        val vc = "SSH-2.0-Client".toByteArray()
        val vs = "SSH-2.0-Server".toByteArray()
        val ic = ByteArray(16) { it.toByte() }
        val is_ = ByteArray(16) { (it + 16).toByte() }
        val ks = ByteArray(32) { (it + 32).toByte() }
        val e = ByteArray(32) { (it + 64).toByte() }
        val f = ByteArray(32) { (it + 96).toByte() }
        val k = ByteArray(32) { (it + 128).toByte() }

        val h1 = gex.computeExchangeHash(vc, vs, ic, is_, ks, e, f, k)
        val h2 = gex.computeExchangeHash(vc, vs, ic, is_, ks, e, f, k)

        assertContentEquals(h1, h2)
        assertTrue(h1.isNotEmpty())
    }

    @Test
    fun `exchange hash uses SHA-256`() {
        val gex = DiffieHellmanGroupExchange("SHA-256")
        gex.setGroup(DhGroups.GROUP14_P, DhGroups.GENERATOR)

        val h = gex.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
        )
        assertEquals(32, h.size)
    }

    @Test
    fun `exchange hash uses SHA-1`() {
        val gex = DiffieHellmanGroupExchange("SHA-1")
        gex.setGroup(DhGroups.GROUP14_P, DhGroups.GENERATOR)

        val h = gex.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
        )
        assertEquals(20, h.size)
    }
}
