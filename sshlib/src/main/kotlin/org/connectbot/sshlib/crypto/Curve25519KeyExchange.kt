/*
 * ConnectBot SSH Library
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

internal class Curve25519KeyExchange(
    private val x25519Provider: X25519Provider = X25519ProviderFactory.provider,
    private val presetPrivateKey: ByteArray? = null,
) : KexAlgorithm {

    override val hashAlgorithm: String = "SHA-256"

    private var clientPrivate: ByteArray? = null

    override fun generateClientKeys(): ByteArray {
        val clientPrivate = presetPrivateKey?.clone() ?: x25519Provider.generatePrivateKey()

        this.clientPrivate = clientPrivate

        return try {
            x25519Provider.publicFromPrivate(clientPrivate)
        } catch (e: Exception) {
            throw SshException("Failed to generate X25519 public key", e)
        }
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val privKey = clientPrivate
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")

        if (serverPublicKey.size != X25519Provider.KEY_SIZE) {
            throw SshException(
                "Invalid server key length ${serverPublicKey.size} (expected ${X25519Provider.KEY_SIZE})",
            )
        }

        try {
            val sharedSecretBytes = x25519Provider.computeSharedSecret(privKey, serverPublicKey)

            var allZero = true
            for (b in sharedSecretBytes) {
                if (b.toInt() != 0) {
                    allZero = false
                    break
                }
            }
            if (allZero) {
                throw SshException("Invalid key computed; all zeroes")
            }

            return encodeMpint(BigInteger(1, sharedSecretBytes).toByteArray())
        } catch (e: SshException) {
            throw e
        } catch (e: Exception) {
            throw SshException("X25519 key agreement failed", e)
        }
    }

    override fun zeroize() {
        clientPrivate?.fill(0)
        clientPrivate = null
    }
}
