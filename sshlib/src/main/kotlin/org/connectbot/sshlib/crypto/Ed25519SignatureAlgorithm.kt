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

import org.connectbot.sshlib.protocol.SshEd25519PublicKeyBlob
import org.connectbot.sshlib.protocol.SshEd25519SignatureBlob
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

internal object Ed25519SignatureAlgorithm : SshSignatureAlgorithm {
    private val ED25519_OID = byteArrayOf(0x2b, 0x65, 0x70) // 1.3.101.112

    override fun verify(pubKey: SshPublicKey, sig: SshSignature, data: ByteArray): Boolean {
        val keyBlob = pubKey.keyBlob() as SshEd25519PublicKeyBlob
        val rawKey = keyBlob.key().data()

        val x509Key = encodeDer {
            sequence {
                sequence {
                    objectIdentifier(ED25519_OID)
                }
                bitString(rawKey)
            }
        }
        val keySpec = X509EncodedKeySpec(x509Key)
        val jcaKey = KeyFactory.getInstance("Ed25519").generatePublic(keySpec)

        val sigBlob = sig.signatureBlob() as SshEd25519SignatureBlob
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(jcaKey)
        verifier.update(data)
        return verifier.verify(sigBlob.signature().data())
    }

    override fun sign(algorithmName: String, privateKey: PrivateKey, data: ByteArray): ByteArray {
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(privateKey)
        signer.update(data)
        val sigBytes = signer.sign()
        return encodeSshString("ssh-ed25519".toByteArray(Charsets.US_ASCII)) +
            encodeSshString(sigBytes)
    }
}
