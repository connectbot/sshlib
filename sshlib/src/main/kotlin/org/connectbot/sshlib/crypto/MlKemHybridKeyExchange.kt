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
import java.security.MessageDigest

/**
 * ML-KEM-768 hybrid key exchange (mlkem768x25519-sha256).
 *
 * Combines post-quantum ML-KEM-768 with classical X25519.
 * Implements draft-ietf-sshm-mlkem-hybrid-kex.
 *
 * Client init message: mlkem_pubkey (1184) || x25519_pubkey (32) = 1216 bytes
 * Server reply: mlkem_ciphertext (1088) || x25519_pubkey (32) = 1120 bytes
 * K = SHA-256(mlkem_ss || x25519_ss)
 */
internal class MlKemHybridKeyExchange(
    private val mlKemProvider: MlKemProvider = MlKemProviderFactory.provider,
    private val x25519Provider: X25519Provider = X25519ProviderFactory.provider
) : KexAlgorithm {
    companion object {
        private const val MLKEM768_PUBLIC_KEY_SIZE = 1184
        private const val MLKEM768_CIPHERTEXT_SIZE = 1088
        private const val MLKEM768_SHARED_SECRET_SIZE = 32
        private const val X25519_KEY_SIZE = 32
    }

    override val hashAlgorithm: String = "SHA-256"

    private var mlKemPrivateKey: ByteArray? = null
    private var x25519PrivateKey: ByteArray? = null

    override fun generateClientKeys(): ByteArray {
        val mlKemKeyPair = mlKemProvider.generateKeyPair()
        val mlKemPublicKey = mlKemKeyPair.publicKey
        mlKemPrivateKey = mlKemKeyPair.privateKey

        if (mlKemPublicKey.size != MLKEM768_PUBLIC_KEY_SIZE) {
            throw SshException(
                "Unexpected ML-KEM-768 public key size: ${mlKemPublicKey.size} (expected $MLKEM768_PUBLIC_KEY_SIZE)"
            )
        }

        x25519PrivateKey = x25519Provider.generatePrivateKey()
        val x25519PublicKey = try {
            x25519Provider.publicFromPrivate(x25519PrivateKey!!)
        } catch (e: Exception) {
            throw SshException("Failed to generate X25519 public key", e)
        }

        if (x25519PublicKey.size != X25519_KEY_SIZE) {
            throw SshException(
                "Unexpected X25519 public key size: ${x25519PublicKey.size} (expected $X25519_KEY_SIZE)"
            )
        }

        val init = ByteArray(mlKemPublicKey.size + x25519PublicKey.size)
        System.arraycopy(mlKemPublicKey, 0, init, 0, mlKemPublicKey.size)
        System.arraycopy(x25519PublicKey, 0, init, mlKemPublicKey.size, x25519PublicKey.size)
        return init
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val mlKemPriv = mlKemPrivateKey
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        val x25519Priv = x25519PrivateKey
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")

        val expectedSize = MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE
        if (serverPublicKey.size != expectedSize) {
            throw SshException(
                "Invalid S_REPLY length: ${serverPublicKey.size} (expected $expectedSize)"
            )
        }

        val mlKemCiphertext = ByteArray(MLKEM768_CIPHERTEXT_SIZE)
        System.arraycopy(serverPublicKey, 0, mlKemCiphertext, 0, MLKEM768_CIPHERTEXT_SIZE)

        val serverX25519PublicKey = ByteArray(X25519_KEY_SIZE)
        System.arraycopy(serverPublicKey, MLKEM768_CIPHERTEXT_SIZE, serverX25519PublicKey, 0, X25519_KEY_SIZE)

        try {
            val mlKemSharedSecret = mlKemProvider.decapsulate(mlKemPriv, mlKemCiphertext)

            val x25519SharedSecret = x25519Provider.computeSharedSecret(x25519Priv, serverX25519PublicKey)
            validateNotAllZeros(x25519SharedSecret)

            val combined = ByteArray(MLKEM768_SHARED_SECRET_SIZE + X25519_KEY_SIZE)
            System.arraycopy(mlKemSharedSecret, 0, combined, 0, MLKEM768_SHARED_SECRET_SIZE)
            System.arraycopy(x25519SharedSecret, 0, combined, MLKEM768_SHARED_SECRET_SIZE, X25519_KEY_SIZE)

            return encodeSshString(MessageDigest.getInstance("SHA-256").digest(combined))
        } catch (e: SshException) {
            throw e
        } catch (e: Exception) {
            throw SshException("ML-KEM hybrid key exchange failed", e)
        }
    }

    private fun validateNotAllZeros(secret: ByteArray) {
        var allZero = true
        for (b in secret) {
            if (b.toInt() != 0) {
                allZero = false
                break
            }
        }
        if (allZero) {
            throw SshException("Invalid X25519 shared secret; all zeroes")
        }
    }
}
