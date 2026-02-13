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
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Diffie-Hellman Group Exchange key exchange (RFC 4419).
 *
 * Uses a 4-message protocol where the client requests DH parameters from
 * the server before performing the key exchange.
 */
internal class DiffieHellmanGroupExchange(override val hashAlgorithm: String) : KexAlgorithm {
    companion object {
        private val secureRandom = SecureRandom()
    }

    val min = 2048
    val n = 4096
    val max = 8192

    private var p: BigInteger? = null
    private var g: BigInteger? = null
    private var privateKey: BigInteger? = null

    fun setGroup(p: BigInteger, g: BigInteger) {
        this.p = p
        this.g = g
    }

    override fun generateClientKeys(): ByteArray {
        val p = this.p ?: throw SshException("DH group not set; call setGroup() first")
        val g = this.g ?: throw SshException("DH group not set; call setGroup() first")

        val x = BigInteger(p.bitLength(), secureRandom).mod(p - BigInteger.ONE) + BigInteger.ONE
        privateKey = x
        val e = g.modPow(x, p)
        return e.toByteArray()
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val x = privateKey
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        val p = this.p ?: throw SshException("DH group not set; call setGroup() first")
        val f = BigInteger(1, serverPublicKey)

        if (f <= BigInteger.ONE || f >= p - BigInteger.ONE) {
            throw SshException("Invalid server public key")
        }

        return encodeMpint(f.modPow(x, p).toByteArray())
    }

    /**
     * Compute exchange hash H per RFC 4419 Section 3.
     *
     * H = hash(V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K)
     */
    override fun computeExchangeHash(
        clientVersion: ByteArray,
        serverVersion: ByteArray,
        clientKexInit: ByteArray,
        serverKexInit: ByteArray,
        serverHostKey: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray,
        sharedSecret: ByteArray,
    ): ByteArray {
        val p = this.p ?: throw SshException("DH group not set; call setGroup() first")
        val g = this.g ?: throw SshException("DH group not set; call setGroup() first")

        val transcript = ByteArrayOutputStream()

        fun writeString(data: ByteArray) {
            val len = data.size
            transcript.write(
                byteArrayOf(
                    (len shr 24).toByte(),
                    (len shr 16).toByte(),
                    (len shr 8).toByte(),
                    len.toByte()
                )
            )
            transcript.write(data)
        }

        fun writeUint32(value: Int) {
            transcript.write(
                byteArrayOf(
                    (value shr 24).toByte(),
                    (value shr 16).toByte(),
                    (value shr 8).toByte(),
                    value.toByte()
                )
            )
        }

        writeString(clientVersion)
        writeString(serverVersion)
        writeString(clientKexInit)
        writeString(serverKexInit)
        writeString(serverHostKey)
        writeUint32(min)
        writeUint32(n)
        writeUint32(max)
        writeString(p.toByteArray())
        writeString(g.toByteArray())
        writeString(clientPublicKey)
        writeString(serverPublicKey)
        transcript.write(sharedSecret)

        val md = MessageDigest.getInstance(hashAlgorithm)
        return md.digest(transcript.toByteArray())
    }
}
