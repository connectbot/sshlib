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
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * SSH key derivation as specified in RFC 4253 section 7.2.
 *
 * Keys are derived from shared secret K, exchange hash H, and session ID.
 * The session ID is H from the first key exchange.
 */
class KeyDerivation(
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
     * Derive a single key according to RFC 4253.
     *
     * Key derivation formula:
     * - Initial key: HASH(K || H || X || session_id)
     * - Extended key: HASH(K || H || initial_key)
     * - Continue extending: HASH(K || H || previous_key)
     *
     * Where X is a single character: 'A' to 'F' as specified in RFC 4253.
     *
     * @param keyId Key identifier ('A' through 'F')
     * @param length Required key length in bytes
     * @return Derived key
     */
    private fun deriveKey(keyId: Char, length: Int): ByteArray {
        val result = ByteArray(length)
        var offset = 0

        val md = MessageDigest.getInstance(hashAlgorithm)
        val digestLength = md.digestLength

        // Convert shared secret to mpint format (SSH integer)
        val kBytes = toMpint(sharedSecret)

        // First iteration: HASH(K || H || X || session_id)
        md.update(kBytes)
        md.update(exchangeHash)
        md.update(keyId.code.toByte())
        md.update(sessionId)
        var key = md.digest()

        // Copy first chunk
        val toCopy = minOf(key.size, length - offset)
        System.arraycopy(key, 0, result, offset, toCopy)
        offset += toCopy

        // Additional iterations if needed: HASH(K || H || previous_key)
        while (offset < length) {
            md.reset()
            md.update(kBytes)
            md.update(exchangeHash)
            md.update(key)
            key = md.digest()

            val remaining = length - offset
            val copySize = minOf(key.size, remaining)
            System.arraycopy(key, 0, result, offset, copySize)
            offset += copySize
        }

        return result
    }

    /**
     * Convert byte array to SSH mpint format (RFC 4251 section 5).
     *
     * mpint format:
     * - 4-byte length prefix (network byte order)
     * - If high bit is set, prepend 0x00 to avoid being interpreted as negative
     * - Remove leading zero bytes (except the one added above if needed)
     */
    private fun toMpint(value: ByteArray): ByteArray {
        // Remove leading zeros
        var start = 0
        while (start < value.size - 1 && value[start] == 0.toByte()) {
            start++
        }

        // Check if we need to add 0x00 to keep it positive
        val needsPadding = value[start].toInt() and 0x80 != 0

        val dataBytes = if (needsPadding) {
            ByteArray(value.size - start + 1).apply {
                this[0] = 0
                System.arraycopy(value, start, this, 1, value.size - start)
            }
        } else {
            value.copyOfRange(start, value.size)
        }

        // Add 4-byte length prefix
        val result = ByteArray(4 + dataBytes.size)
        result[0] = (dataBytes.size shr 24).toByte()
        result[1] = (dataBytes.size shr 16).toByte()
        result[2] = (dataBytes.size shr 8).toByte()
        result[3] = dataBytes.size.toByte()
        System.arraycopy(dataBytes, 0, result, 4, dataBytes.size)

        return result
    }
}
