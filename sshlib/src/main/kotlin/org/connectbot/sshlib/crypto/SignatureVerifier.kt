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

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.struct.SshPublicKey
import org.connectbot.sshlib.struct.SshSignature

object SignatureVerifier {

    fun verify(serverHostKey: ByteArray, signatureData: ByteArray, exchangeHash: ByteArray): Boolean {
        val sig = SshSignature(ByteBufferKaitaiStream(signatureData))
        sig._read()

        val pubKey = SshPublicKey(ByteBufferKaitaiStream(serverHostKey))
        pubKey._read()

        val algorithm = when (sig.algorithmName()) {
            "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512" -> RsaSignatureAlgorithm
            "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" -> EcdsaSignatureAlgorithm
            "ssh-ed25519" -> Ed25519SignatureAlgorithm
            "ssh-ed448" -> Ed448SignatureAlgorithm
            else -> return false
        }

        return algorithm.verify(pubKey, sig, exchangeHash)
    }
}
