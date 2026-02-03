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

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Common interface for SSH key exchange algorithms.
 *
 * Both classic Diffie-Hellman (RFC 4253) and ECDH (RFC 5656) follow the same
 * pattern: generate an ephemeral key pair, compute a shared secret from the
 * server's public value, and compute an exchange hash over the transcript.
 */
interface KexAlgorithm {
    val hashAlgorithm: String

    fun generateClientKeys(): ByteArray

    /**
     * Compute the shared secret K from the server's public value.
     *
     * The returned bytes are the wire-encoded K, ready for use in the exchange
     * hash and key derivation. For classic DH/ECDH this is mpint encoding
     * (uint32 length + positive integer bytes). For ML-KEM hybrid this is SSH
     * string encoding (uint32 length + raw hash bytes).
     */
    fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray

    /**
     * Compute exchange hash H over the key exchange transcript.
     *
     * H = hash(V_C || V_S || I_C || I_S || K_S || e/Q_C || f/Q_S || K)
     *
     * All values except K are encoded as SSH strings (uint32 length + data).
     * K is already wire-encoded by [computeSharedSecret] and written directly.
     */
    fun computeExchangeHash(
        clientVersion: ByteArray,
        serverVersion: ByteArray,
        clientKexInit: ByteArray,
        serverKexInit: ByteArray,
        serverHostKey: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray,
        sharedSecret: ByteArray
    ): ByteArray {
        val transcript = ByteArrayOutputStream()

        fun writeString(data: ByteArray) {
            val len = data.size
            transcript.write(byteArrayOf(
                (len shr 24).toByte(),
                (len shr 16).toByte(),
                (len shr 8).toByte(),
                len.toByte()
            ))
            transcript.write(data)
        }

        writeString(clientVersion)
        writeString(serverVersion)
        writeString(clientKexInit)
        writeString(serverKexInit)
        writeString(serverHostKey)
        writeString(clientPublicKey)
        writeString(serverPublicKey)
        transcript.write(sharedSecret)

        val md = MessageDigest.getInstance(hashAlgorithm)
        return md.digest(transcript.toByteArray())
    }
}
