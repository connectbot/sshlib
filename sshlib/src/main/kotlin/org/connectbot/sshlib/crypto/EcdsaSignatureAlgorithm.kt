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
import org.connectbot.sshlib.protocol.EcdsaPublicKeyBlob
import org.connectbot.sshlib.protocol.EcdsaSignatureBlob
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

internal object EcdsaSignatureAlgorithm : SshSignatureAlgorithm {
    override fun verify(pubKey: SshPublicKey, sig: SshSignature, data: ByteArray): Boolean {
        val keyBlob = pubKey.keyBlob() as EcdsaPublicKeyBlob
        val curveName = keyBlob.curveIdentifier().value()
        val qBytes = keyBlob.q().data()

        val (ecSpec, jcaAlgorithm) = when (curveName) {
            "nistp256" -> ECGenParameterSpec("secp256r1") to "SHA256withECDSA"
            "nistp384" -> ECGenParameterSpec("secp384r1") to "SHA384withECDSA"
            "nistp521" -> ECGenParameterSpec("secp521r1") to "SHA512withECDSA"
            else -> return false
        }

        val params = AlgorithmParameters.getInstance("EC")
        params.init(ecSpec)
        val paramSpec = params.getParameterSpec(ECParameterSpec::class.java)

        val point = decodeEcPoint(qBytes, paramSpec)
        val keySpec = ECPublicKeySpec(point, paramSpec)
        val jcaKey = KeyFactory.getInstance("EC").generatePublic(keySpec)

        val sigBlob = sig.signatureBlob() as EcdsaSignatureBlob
        val r = BigInteger(1, sigBlob.blob().r().body())
        val s = BigInteger(1, sigBlob.blob().s().body())
        val derSig = encodeDerEcdsaSignature(r, s)

        val verifier = Signature.getInstance(jcaAlgorithm)
        verifier.initVerify(jcaKey)
        verifier.update(data)
        return verifier.verify(derSig)
    }

    internal fun decodeEcPoint(encoded: ByteArray, spec: ECParameterSpec): ECPoint {
        val fieldSize = (spec.order.bitLength() + 7) / 8
        if (encoded[0] != 0x04.toByte() || encoded.size != 1 + 2 * fieldSize) {
            throw SshException("Invalid EC point encoding")
        }
        val x = BigInteger(1, encoded, 1, fieldSize)
        val y = BigInteger(1, encoded, 1 + fieldSize, fieldSize)
        return ECPoint(x, y)
    }

    internal fun encodeDerEcdsaSignature(r: BigInteger, s: BigInteger): ByteArray = encodeDer {
        sequence {
            integer(r)
            integer(s)
        }
    }

    internal fun decodeDerEcdsaSignature(derSig: ByteArray): Pair<BigInteger, BigInteger> {
        val reader = DerReader(derSig)
        return reader.readSequence { seq ->
            val r = seq.readInteger()
            val s = seq.readInteger()
            r to s
        }
    }

    override fun sign(algorithmName: String, privateKey: PrivateKey, data: ByteArray): ByteArray {
        val ecKey = privateKey as ECKey
        val fieldSize = (ecKey.params.order.bitLength() + 7) / 8

        val jcaAlgorithm = when (fieldSize) {
            32 -> "SHA256withECDSA"
            48 -> "SHA384withECDSA"
            66 -> "SHA512withECDSA"
            else -> throw SshException("Unsupported EC key size: $fieldSize")
        }

        val signer = Signature.getInstance(jcaAlgorithm)
        signer.initSign(privateKey)
        signer.update(data)
        val derSig = signer.sign()

        val (r, s) = decodeDerEcdsaSignature(derSig)
        val sshSigBlob = encodeMpint(r.toByteArray()) + encodeMpint(s.toByteArray())

        return encodeSshString(algorithmName.toByteArray(Charsets.US_ASCII)) +
            encodeSshString(sshSigBlob)
    }
}
