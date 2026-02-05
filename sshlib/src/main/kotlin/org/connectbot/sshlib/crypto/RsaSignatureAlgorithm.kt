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

import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshRsaPublicKeyBlob
import org.connectbot.sshlib.protocol.SshRsaSignatureBlob
import org.connectbot.sshlib.protocol.SshSignature
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec

internal object RsaSignatureAlgorithm : SshSignatureAlgorithm {
    override fun verify(pubKey: SshPublicKey, sig: SshSignature, data: ByteArray): Boolean {
        val keyBlob = pubKey.keyBlob() as SshRsaPublicKeyBlob
        val e = BigInteger(1, keyBlob.e().body())
        val n = BigInteger(1, keyBlob.n().body())
        val spec = RSAPublicKeySpec(n, e)
        val jcaKey = KeyFactory.getInstance("RSA").generatePublic(spec)

        val jcaAlgorithm = when (sig.algorithmName()) {
            "rsa-sha2-512" -> "SHA512withRSA"
            else -> "SHA256withRSA"
        }

        val sigBlob = sig.signatureBlob() as SshRsaSignatureBlob
        val verifier = Signature.getInstance(jcaAlgorithm)
        verifier.initVerify(jcaKey)
        verifier.update(data)
        return verifier.verify(sigBlob.signature().data())
    }

    override fun sign(algorithmName: String, privateKey: java.security.PrivateKey, data: ByteArray): ByteArray {
        val jcaAlgorithm = when (algorithmName) {
            "rsa-sha2-512" -> "SHA512withRSA"
            else -> "SHA256withRSA"
        }

        val signer = Signature.getInstance(jcaAlgorithm)
        signer.initSign(privateKey)
        signer.update(data)
        val sigBytes = signer.sign()

        return encodeSshString(algorithmName.toByteArray(Charsets.US_ASCII)) +
                encodeSshString(sigBytes)
    }
}
