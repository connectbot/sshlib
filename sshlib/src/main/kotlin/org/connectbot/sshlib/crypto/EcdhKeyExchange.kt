/*
 * ConnectBot SSH Library
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
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import javax.security.auth.DestroyFailedException
import javax.security.auth.Destroyable

/**
 * Elliptic Curve Diffie-Hellman key exchange as specified in RFC 5656 Section 4.
 *
 * Supports the three required NIST curves: nistp256, nistp384, nistp521.
 */
internal class EcdhKeyExchange(private val curveName: String) : KexAlgorithm {

    private val jcaCurveName: String
    private val ecParameterSpec: ECParameterSpec
    private val fieldSize: Int
    override val hashAlgorithm: String

    private var clientKeyPair: KeyPair? = null

    init {
        val (jcaName, hash) = when (curveName) {
            "nistp256" -> "secp256r1" to "SHA-256"
            "nistp384" -> "secp384r1" to "SHA-384"
            "nistp521" -> "secp521r1" to "SHA-512"
            else -> throw SshException("Unsupported ECDH curve: $curveName")
        }
        jcaCurveName = jcaName
        hashAlgorithm = hash

        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec(jcaCurveName))
        ecParameterSpec = params.getParameterSpec(ECParameterSpec::class.java)
        fieldSize = (ecParameterSpec.order.bitLength() + 7) / 8
    }

    /**
     * Generate client's ephemeral EC key pair.
     *
     * @return Q_C as SEC1 uncompressed point (0x04 || x || y)
     */
    override fun generateClientKeys(): ByteArray {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec(jcaCurveName))
        clientKeyPair = kpg.generateKeyPair()

        val pub = clientKeyPair?.public as? ECPublicKey
            ?: throw SshException("Failed to generate EC key pair")
        return encodeEcPoint(pub.w)
    }

    /**
     * Compute shared secret from server's ephemeral public key.
     *
     * @param serverPublicKey Q_S as SEC1 uncompressed point
     * @return shared secret K as BigInteger byte array (positive, suitable for mpint encoding)
     */
    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val kp = clientKeyPair
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        try {
            val serverPoint = decodeEcPoint(serverPublicKey)
            val serverPubKeySpec = ECPublicKeySpec(serverPoint, ecParameterSpec)
            val serverPubKey = KeyFactory.getInstance("EC").generatePublic(serverPubKeySpec)

            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(kp.private)
            agreement.doPhase(serverPubKey, true)
            val rawSecret = agreement.generateSecret()

            return encodeMpint(BigInteger(1, rawSecret).toByteArray())
        } catch (e: SshException) {
            throw e
        } catch (e: Exception) {
            throw SshException("Invalid server ECDH public key: ${e.message}", e)
        }
    }

    private fun encodeEcPoint(point: ECPoint): ByteArray {
        val x = point.affineX.toByteArray()
        val y = point.affineY.toByteArray()
        val result = ByteArray(1 + 2 * fieldSize)
        result[0] = 0x04
        System.arraycopy(
            x,
            maxOf(0, x.size - fieldSize),
            result,
            1 + fieldSize - minOf(x.size, fieldSize),
            minOf(x.size, fieldSize),
        )
        System.arraycopy(
            y,
            maxOf(0, y.size - fieldSize),
            result,
            1 + 2 * fieldSize - minOf(y.size, fieldSize),
            minOf(y.size, fieldSize),
        )
        return result
    }

    private fun decodeEcPoint(encoded: ByteArray): ECPoint {
        if (encoded.isEmpty() || encoded[0] != 0x04.toByte() || encoded.size != 1 + 2 * fieldSize) {
            throw SshException("Invalid EC point encoding")
        }
        val x = BigInteger(1, encoded, 1, fieldSize)
        val y = BigInteger(1, encoded, 1 + fieldSize, fieldSize)
        return ECPoint(x, y)
    }

    override fun zeroize() {
        val kp = clientKeyPair
        clientKeyPair = null
        try {
            (kp?.private as? Destroyable)?.destroy()
        } catch (_: DestroyFailedException) {
        }
    }
}
