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
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class EcdhKeyExchangeTest {

    @Test
    fun `nistp256 generates valid uncompressed EC point`() {
        val ecdh = EcdhKeyExchange("nistp256")
        val qc = ecdh.generateClientKeys()

        assertEquals(0x04, qc[0].toInt() and 0xFF)
        assertEquals(1 + 2 * 32, qc.size)
    }

    @Test
    fun `nistp384 generates valid uncompressed EC point`() {
        val ecdh = EcdhKeyExchange("nistp384")
        val qc = ecdh.generateClientKeys()

        assertEquals(0x04, qc[0].toInt() and 0xFF)
        assertEquals(1 + 2 * 48, qc.size)
    }

    @Test
    fun `nistp521 generates valid uncompressed EC point`() {
        val ecdh = EcdhKeyExchange("nistp521")
        val qc = ecdh.generateClientKeys()

        assertEquals(0x04, qc[0].toInt() and 0xFF)
        assertEquals(1 + 2 * 66, qc.size)
    }

    @Test
    fun `shared secret matches for nistp256`() {
        verifySharedSecret("nistp256", "secp256r1")
    }

    @Test
    fun `shared secret matches for nistp384`() {
        verifySharedSecret("nistp384", "secp384r1")
    }

    @Test
    fun `shared secret matches for nistp521`() {
        verifySharedSecret("nistp521", "secp521r1")
    }

    private fun verifySharedSecret(curveName: String, jcaCurve: String) {
        val client = EcdhKeyExchange(curveName)
        val qc = client.generateClientKeys()

        // Simulate server side using raw JCA
        val serverKpg = KeyPairGenerator.getInstance("EC")
        serverKpg.initialize(ECGenParameterSpec(jcaCurve))
        val serverKp = serverKpg.generateKeyPair()
        val serverPub = serverKp.public as ECPublicKey

        val fieldSize = (serverPub.params.order.bitLength() + 7) / 8
        val x = serverPub.w.affineX.toByteArray()
        val y = serverPub.w.affineY.toByteArray()
        val qs = ByteArray(1 + 2 * fieldSize)
        qs[0] = 0x04
        System.arraycopy(x, maxOf(0, x.size - fieldSize), qs, 1 + fieldSize - minOf(x.size, fieldSize), minOf(x.size, fieldSize))
        System.arraycopy(y, maxOf(0, y.size - fieldSize), qs, 1 + 2 * fieldSize - minOf(y.size, fieldSize), minOf(y.size, fieldSize))

        val clientSecret = client.computeSharedSecret(qs)

        // Server computes shared secret from client's Q_C
        val serverAgreement = KeyAgreement.getInstance("ECDH")
        serverAgreement.init(serverKp.private)

        val clientPoint = EcdsaSignatureAlgorithm.decodeEcPoint(qc, serverPub.params)
        val clientPubKey = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(clientPoint, serverPub.params))
        serverAgreement.doPhase(clientPubKey, true)
        val serverRawSecret = serverAgreement.generateSecret()

        val serverBigInt = BigInteger(1, serverRawSecret)
        val serverSecret = encodeMpint(serverBigInt.toByteArray())

        assertContentEquals(serverSecret, clientSecret)
    }

    @Test
    fun `rejects invalid EC point`() {
        val ecdh = EcdhKeyExchange("nistp256")
        ecdh.generateClientKeys()

        val invalidPoint = ByteArray(65)
        invalidPoint[0] = 0x04
        // All zeros is not a valid point on any curve

        assertFailsWith<SshException> {
            ecdh.computeSharedSecret(invalidPoint)
        }
    }

    @Test
    fun `rejects unknown curve`() {
        assertFailsWith<SshException> {
            EcdhKeyExchange("nistfoo")
        }
    }

    @Test
    fun `exchange hash is deterministic`() {
        val ecdh = EcdhKeyExchange("nistp256")
        ecdh.generateClientKeys()

        val vc = "SSH-2.0-Client".toByteArray()
        val vs = "SSH-2.0-Server".toByteArray()
        val ic = ByteArray(16) { it.toByte() }
        val is_ = ByteArray(16) { (it + 16).toByte() }
        val ks = ByteArray(32) { (it + 32).toByte() }
        val qc = ByteArray(65) { (it + 64).toByte() }
        val qs = ByteArray(65) { (it + 128).toByte() }
        val k = ByteArray(32) { (it + 192).toByte() }

        val h1 = ecdh.computeExchangeHash(vc, vs, ic, is_, ks, qc, qs, k)
        val h2 = ecdh.computeExchangeHash(vc, vs, ic, is_, ks, qc, qs, k)

        assertContentEquals(h1, h2)
        assertTrue(h1.isNotEmpty())
    }

    @Test
    fun `exchange hash uses SHA-256 for nistp256`() {
        val ecdh = EcdhKeyExchange("nistp256")
        ecdh.generateClientKeys()

        val h = ecdh.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
        )
        assertEquals(32, h.size) // SHA-256 output
    }

    @Test
    fun `exchange hash uses SHA-384 for nistp384`() {
        val ecdh = EcdhKeyExchange("nistp384")
        ecdh.generateClientKeys()

        val h = ecdh.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
        )
        assertEquals(48, h.size) // SHA-384 output
    }

    @Test
    fun `exchange hash uses SHA-512 for nistp521`() {
        val ecdh = EcdhKeyExchange("nistp521")
        ecdh.generateClientKeys()

        val h = ecdh.computeExchangeHash(
            "V_C".toByteArray(),
            "V_S".toByteArray(),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
            ByteArray(1),
        )
        assertEquals(64, h.size) // SHA-512 output
    }
}
