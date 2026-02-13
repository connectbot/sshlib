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
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Diffie-Hellman key exchange implementation for SSH (RFC 4253).
 */
internal class DiffieHellman(
    override val hashAlgorithm: String = "SHA-256",
    private val p: BigInteger = DhGroups.GROUP14_P,
    private val g: BigInteger = DhGroups.GENERATOR,
) : KexAlgorithm {
    companion object {
        private val secureRandom = SecureRandom()
    }

    private var privateKey: BigInteger? = null
    private var publicKey: BigInteger? = null

    override fun generateClientKeys(): ByteArray {
        val x = BigInteger(p.bitLength(), secureRandom).mod(p - BigInteger.ONE) + BigInteger.ONE
        privateKey = x
        val e = g.modPow(x, p)
        publicKey = e
        return e.toByteArray()
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val x = privateKey
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        val f = BigInteger(1, serverPublicKey)

        if (f <= BigInteger.ONE || f >= p - BigInteger.ONE) {
            throw SshException("Invalid server public key")
        }

        return encodeMpint(f.modPow(x, p).toByteArray())
    }
}
