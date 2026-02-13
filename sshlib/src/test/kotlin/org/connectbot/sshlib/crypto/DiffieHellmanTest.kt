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
import java.security.KeyFactory
import java.security.KeyPairGenerator
import javax.crypto.KeyAgreement
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.DHPublicKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DiffieHellmanTest {

    @Test
    fun `group 14 generates valid public key`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)
        val e = dh.generateClientKeys()
        val pubKey = BigInteger(1, e)
        assertTrue(pubKey > BigInteger.ONE)
        assertTrue(pubKey < DhGroups.GROUP14_P - BigInteger.ONE)
    }

    @Test
    fun `group 16 generates valid public key`() {
        val dh = DiffieHellman("SHA-512", DhGroups.GROUP16_P, DhGroups.GENERATOR)
        val e = dh.generateClientKeys()
        val pubKey = BigInteger(1, e)
        assertTrue(pubKey > BigInteger.ONE)
        assertTrue(pubKey < DhGroups.GROUP16_P - BigInteger.ONE)
    }

    @Test
    fun `group 18 generates valid public key`() {
        val dh = DiffieHellman("SHA-512", DhGroups.GROUP18_P, DhGroups.GENERATOR)
        val e = dh.generateClientKeys()
        val pubKey = BigInteger(1, e)
        assertTrue(pubKey > BigInteger.ONE)
        assertTrue(pubKey < DhGroups.GROUP18_P - BigInteger.ONE)
    }

    @Test
    fun `group 1 generates valid public key`() {
        val dh = DiffieHellman("SHA-1", DhGroups.GROUP1_P, DhGroups.GENERATOR)
        val e = dh.generateClientKeys()
        val pubKey = BigInteger(1, e)
        assertTrue(pubKey > BigInteger.ONE)
        assertTrue(pubKey < DhGroups.GROUP1_P - BigInteger.ONE)
    }

    @Test
    fun `shared secret agreement with group 14`() {
        verifySharedSecret(DhGroups.GROUP14_P, DhGroups.GENERATOR)
    }

    @Test
    fun `shared secret agreement with group 1`() {
        verifySharedSecret(DhGroups.GROUP1_P, DhGroups.GENERATOR)
    }

    private fun verifySharedSecret(p: BigInteger, g: BigInteger) {
        val client = DiffieHellman("SHA-256", p, g)
        val e = client.generateClientKeys()

        // Simulate server using JCA DH
        val serverKpg = KeyPairGenerator.getInstance("DH")
        serverKpg.initialize(DHParameterSpec(p, g))
        val serverKp = serverKpg.generateKeyPair()
        val serverPub = serverKp.public as DHPublicKey
        val f = serverPub.y.toByteArray()

        val clientSecret = client.computeSharedSecret(f)

        // Server computes shared secret from client's e
        val serverAgreement = KeyAgreement.getInstance("DH")
        serverAgreement.init(serverKp.private)

        val clientPubKeySpec = DHPublicKeySpec(BigInteger(1, e), p, g)
        val clientPubKey = KeyFactory.getInstance("DH")
            .generatePublic(clientPubKeySpec)
        serverAgreement.doPhase(clientPubKey, true)
        val serverRawSecret = serverAgreement.generateSecret()

        val serverBigInt = BigInteger(1, serverRawSecret)
        val serverSecret = encodeMpint(serverBigInt.toByteArray())

        assertContentEquals(serverSecret, clientSecret)
    }

    @Test
    fun `rejects server public key of 1`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)
        dh.generateClientKeys()

        assertFailsWith<SshException> {
            dh.computeSharedSecret(BigInteger.ONE.toByteArray())
        }
    }

    @Test
    fun `rejects server public key of 0`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)
        dh.generateClientKeys()

        assertFailsWith<SshException> {
            dh.computeSharedSecret(BigInteger.ZERO.toByteArray())
        }
    }

    @Test
    fun `rejects server public key of p minus 1`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)
        dh.generateClientKeys()

        val pMinusOne = DhGroups.GROUP14_P - BigInteger.ONE
        assertFailsWith<SshException> {
            dh.computeSharedSecret(pMinusOne.toByteArray())
        }
    }

    @Test
    fun `computeSharedSecret throws if called before generateClientKeys`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)

        assertFailsWith<SshException> {
            dh.computeSharedSecret(BigInteger.TEN.toByteArray())
        }
    }

    @Test
    fun `exchange hash is deterministic`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)

        val vc = "SSH-2.0-Client".toByteArray()
        val vs = "SSH-2.0-Server".toByteArray()
        val ic = ByteArray(16) { it.toByte() }
        val is_ = ByteArray(16) { (it + 16).toByte() }
        val ks = ByteArray(32) { (it + 32).toByte() }
        val e = ByteArray(32) { (it + 64).toByte() }
        val f = ByteArray(32) { (it + 96).toByte() }
        val k = ByteArray(32) { (it + 128).toByte() }

        val h1 = dh.computeExchangeHash(vc, vs, ic, is_, ks, e, f, k)
        val h2 = dh.computeExchangeHash(vc, vs, ic, is_, ks, e, f, k)

        assertContentEquals(h1, h2)
        assertTrue(h1.isNotEmpty())
    }

    @Test
    fun `exchange hash uses SHA-256`() {
        val dh = DiffieHellman("SHA-256", DhGroups.GROUP14_P, DhGroups.GENERATOR)
        val h = dh.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1)
        )
        assertEquals(32, h.size)
    }

    @Test
    fun `exchange hash uses SHA-512`() {
        val dh = DiffieHellman("SHA-512", DhGroups.GROUP16_P, DhGroups.GENERATOR)
        val h = dh.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1)
        )
        assertEquals(64, h.size)
    }

    @Test
    fun `exchange hash uses SHA-1`() {
        val dh = DiffieHellman("SHA-1", DhGroups.GROUP1_P, DhGroups.GENERATOR)
        val h = dh.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1)
        )
        assertEquals(20, h.size)
    }
}
