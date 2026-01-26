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

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Diffie-Hellman key exchange implementation for SSH.
 *
 * This implements the classic DH key exchange as specified in RFC 4253.
 * For initial implementation, we support DH Group 14 (2048-bit) from RFC 3526.
 */
class DiffieHellman {
    companion object {
        /**
         * DH Group 14 (2048-bit MODP Group) from RFC 3526.
         * This is the "diffie-hellman-group14-sha256" key exchange method.
         */
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

        val GROUP14_G = BigInteger.valueOf(2)

        /**
         * Generate random bytes for private key.
         */
        private val secureRandom = SecureRandom()
    }

    private var privateKey: BigInteger? = null
    private var publicKey: BigInteger? = null
    private var sharedSecret: BigInteger? = null

    /**
     * Generate client's ephemeral key pair.
     *
     * @return Client's public key (e) as byte array
     */
    fun generateClientKeys(): ByteArray {
        // Generate random private key (x)
        // Private key should be in range [1, p-1]
        privateKey = BigInteger(2048, secureRandom).mod(GROUP14_P - BigInteger.ONE) + BigInteger.ONE

        // Calculate public key: e = g^x mod p
        publicKey = GROUP14_G.modPow(privateKey!!, GROUP14_P)

        return publicKey!!.toByteArray()
    }

    /**
     * Compute shared secret from server's public key.
     *
     * @param serverPublicKey Server's public key (f)
     * @return Shared secret (K) as byte array
     */
    fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val f = BigInteger(serverPublicKey)

        // Verify server's public key is in valid range: 1 < f < p-1
        if (f <= BigInteger.ONE || f >= GROUP14_P - BigInteger.ONE) {
            throw IllegalArgumentException("Invalid server public key")
        }

        // Calculate shared secret: K = f^x mod p
        sharedSecret = f.modPow(privateKey!!, GROUP14_P)

        return sharedSecret!!.toByteArray()
    }

    /**
     * Compute exchange hash H according to RFC 4253 section 8.
     *
     * H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
     *
     * @param clientVersion Client version string (V_C)
     * @param serverVersion Server version string (V_S)
     * @param clientKexInit Client's KEX_INIT message (I_C)
     * @param serverKexInit Server's KEX_INIT message (I_S)
     * @param serverHostKey Server's public host key (K_S)
     * @param clientPublicKey Client's public key e
     * @param serverPublicKey Server's public key f
     * @param sharedSecret Shared secret K
     * @param hashAlgorithm Hash algorithm to use (default: SHA-256)
     * @return Exchange hash H
     */
    fun computeExchangeHash(
        clientVersion: ByteArray,
        serverVersion: ByteArray,
        clientKexInit: ByteArray,
        serverKexInit: ByteArray,
        serverHostKey: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray,
        sharedSecret: ByteArray,
        hashAlgorithm: String = "SHA-256"
    ): ByteArray {
        // Build the complete transcript buffer to log it
        val transcript = java.io.ByteArrayOutputStream()

        // All strings and byte arrays must be encoded as SSH strings (length + data)
        fun writeString(data: ByteArray) {
            val lengthBytes = byteArrayOf(
                (data.size shr 24).toByte(),
                (data.size shr 16).toByte(),
                (data.size shr 8).toByte(),
                data.size.toByte()
            )
            transcript.write(lengthBytes)
            transcript.write(data)
        }

        // Write all components in order
        writeString(clientVersion)
        writeString(serverVersion)
        writeString(clientKexInit)
        writeString(serverKexInit)
        writeString(serverHostKey)
        writeString(clientPublicKey)
        writeString(serverPublicKey)
        writeString(sharedSecret)

        val transcriptBytes = transcript.toByteArray()

        // Hash the transcript
        val md = java.security.MessageDigest.getInstance(hashAlgorithm)
        md.update(transcriptBytes)
        return md.digest()
    }
}
