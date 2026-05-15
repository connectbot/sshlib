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

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature

internal object SignatureVerifier {

    /**
     * Verifies the server's host key signature during KEX.
     *
     * Enforces that the algorithm name in the signature blob matches [expectedAlgorithm]
     * (the negotiated host key algorithm), per RFC 8332 §3.2.
     */
    fun verify(serverHostKey: ByteArray, signatureData: ByteArray, exchangeHash: ByteArray, expectedAlgorithm: String): Boolean {
        val sig = SshSignature(ByteBufferKaitaiStream(signatureData))
        sig._read()

        // RFC 8332 §3.2: reject if the algorithm in the signature blob doesn't match
        // what was negotiated. Prevents a server from downgrading e.g. rsa-sha2-256 → ssh-rsa.
        if (sig.algorithmName() != expectedAlgorithm) {
            return false
        }

        val pubKey = SshPublicKey(ByteBufferKaitaiStream(serverHostKey))
        pubKey._read()

        val algorithm = SignatureEntry.fromSshName(sig.algorithmName())?.algorithm
            ?: return false

        return algorithm.verify(pubKey, sig, exchangeHash)
    }

    /**
     * Verifies a signature where the algorithm is self-described in the signature blob
     * (e.g., agent session binding). The algorithm must be compatible with the key type
     * of [hostKey].
     */
    fun verifyWithKeyType(hostKey: ByteArray, signatureData: ByteArray, data: ByteArray): Boolean {
        val sig = SshSignature(ByteBufferKaitaiStream(signatureData))
        sig._read()

        val pubKey = SshPublicKey(ByteBufferKaitaiStream(hostKey))
        pubKey._read()

        val sigAlgorithm = sig.algorithmName()
        val keyType = pubKey.algorithmName()

        // Ensure the sig algorithm is compatible with the key type to prevent cross-type forgery.
        if (!isAlgorithmCompatibleWithKeyType(sigAlgorithm, keyType)) {
            return false
        }

        val algorithm = SignatureEntry.fromSshName(sigAlgorithm)?.algorithm ?: return false
        return algorithm.verify(pubKey, sig, data)
    }

    private fun isAlgorithmCompatibleWithKeyType(sigAlgorithm: String, keyType: String): Boolean = when (keyType) {
        "ssh-rsa" -> sigAlgorithm in setOf("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512")
        else -> sigAlgorithm == keyType
    }
}
