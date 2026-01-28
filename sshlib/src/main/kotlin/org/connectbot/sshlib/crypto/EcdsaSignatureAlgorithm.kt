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

import org.connectbot.sshlib.struct.EcdsaPublicKeyBlob
import org.connectbot.sshlib.struct.EcdsaSignatureBlob
import org.connectbot.sshlib.struct.SshPublicKey
import org.connectbot.sshlib.struct.SshSignature
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

object EcdsaSignatureAlgorithm : SshSignatureAlgorithm {
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

        val params = java.security.AlgorithmParameters.getInstance("EC")
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
            throw IllegalArgumentException("Invalid EC point encoding")
        }
        val x = BigInteger(1, encoded, 1, fieldSize)
        val y = BigInteger(1, encoded, 1 + fieldSize, fieldSize)
        return ECPoint(x, y)
    }

    internal fun encodeDerEcdsaSignature(r: BigInteger, s: BigInteger): ByteArray {
        val rBytes = r.toByteArray()
        val sBytes = s.toByteArray()
        val buf = ByteArrayOutputStream()
        buf.write(0x30) // SEQUENCE
        val contentLen = 2 + rBytes.size + 2 + sBytes.size
        buf.write(contentLen)
        buf.write(0x02) // INTEGER
        buf.write(rBytes.size)
        buf.write(rBytes)
        buf.write(0x02) // INTEGER
        buf.write(sBytes.size)
        buf.write(sBytes)
        return buf.toByteArray()
    }
}
