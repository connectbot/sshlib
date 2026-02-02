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
 * Supports DH Group 14 (2048-bit) from RFC 3526.
 */
class DiffieHellman(override val hashAlgorithm: String = "SHA-256") : KexAlgorithm {
    companion object {
        val GROUP14_P = BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )

        val GROUP14_G: BigInteger = BigInteger.valueOf(2)

        private val secureRandom = SecureRandom()
    }

    private var privateKey: BigInteger? = null
    private var publicKey: BigInteger? = null

    override fun generateClientKeys(): ByteArray {
        val x = BigInteger(2048, secureRandom).mod(GROUP14_P - BigInteger.ONE) + BigInteger.ONE
        privateKey = x
        val e = GROUP14_G.modPow(x, GROUP14_P)
        publicKey = e
        return e.toByteArray()
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val x = privateKey
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        val f = BigInteger(serverPublicKey)

        if (f <= BigInteger.ONE || f >= GROUP14_P - BigInteger.ONE) {
            throw SshException("Invalid server public key")
        }

        return f.modPow(x, GROUP14_P).toByteArray()
    }
}
