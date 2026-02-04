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

import java.security.MessageDigest

/**
 * SSH key derivation as specified in RFC 4253 section 7.2.
 *
 * Keys are derived from shared secret K, exchange hash H, and session ID.
 * The session ID is H from the first key exchange.
 *
 * @param sharedSecret Wire-encoded shared secret K (already in mpint or string format
 *                     with uint32 length prefix, as returned by [KexAlgorithm.computeSharedSecret])
 */
internal class KeyDerivation(
    private val sharedSecret: ByteArray,
    private val exchangeHash: ByteArray,
    private val sessionId: ByteArray,
    private val hashAlgorithm: String = "SHA-1"
) {
    /**
     * Derived encryption/MAC keys for both directions.
     */
    data class Keys(
        val initialIvClientToServer: ByteArray,
        val initialIvServerToClient: ByteArray,
        val encryptionKeyClientToServer: ByteArray,
        val encryptionKeyServerToClient: ByteArray,
        val integrityKeyClientToServer: ByteArray,
        val integrityKeyServerToClient: ByteArray
    )

    /**
     * Derive all keys needed for SSH connection.
     *
     * @param ivLength Required IV length in bytes
     * @param keyLength Required encryption key length in bytes
     * @param macKeyLength Required MAC key length in bytes
     * @return Derived keys
     */
    fun deriveKeys(ivLength: Int, keyLength: Int, macKeyLength: Int): Keys {
        return Keys(
            initialIvClientToServer = deriveKey('A', ivLength),
            initialIvServerToClient = deriveKey('B', ivLength),
            encryptionKeyClientToServer = deriveKey('C', keyLength),
            encryptionKeyServerToClient = deriveKey('D', keyLength),
            integrityKeyClientToServer = deriveKey('E', macKeyLength),
            integrityKeyServerToClient = deriveKey('F', macKeyLength)
        )
    }

    /**
     * Derive a single key according to RFC 4253 section 7.2.
     *
     * K1 = HASH(K || H || X || session_id)
     * K2 = HASH(K || H || K1)
     * K3 = HASH(K || H || K1 || K2)
     * ...
     * key = K1 || K2 || K3 || ... truncated to the required length
     *
     * @param keyId Key identifier ('A' through 'F')
     * @param length Required key length in bytes
     * @return Derived key
     */
    private fun deriveKey(keyId: Char, length: Int): ByteArray {
        val result = ByteArray(length)
        var offset = 0

        val md = MessageDigest.getInstance(hashAlgorithm)

        // K1 = HASH(K || H || X || session_id)
        md.update(sharedSecret)
        md.update(exchangeHash)
        md.update(keyId.code.toByte())
        md.update(sessionId)
        var key = md.digest()

        val toCopy = minOf(key.size, length - offset)
        System.arraycopy(key, 0, result, offset, toCopy)
        offset += toCopy

        // Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
        while (offset < length) {
            md.reset()
            md.update(sharedSecret)
            md.update(exchangeHash)
            md.update(result, 0, offset)
            key = md.digest()

            val remaining = length - offset
            val copySize = minOf(key.size, remaining)
            System.arraycopy(key, 0, result, offset, copySize)
            offset += copySize
        }

        return result
    }
}
