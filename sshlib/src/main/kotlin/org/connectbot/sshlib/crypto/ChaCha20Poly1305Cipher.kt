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

import org.connectbot.sshlib.transport.TransportException
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD cipher for SSH (chacha20-poly1305@openssh.com).
 *
 * Uses two separate ChaCha20 instances:
 * - K_1 (first 32 bytes): encrypts payload, generates Poly1305 key
 * - K_2 (second 32 bytes): encrypts packet length field
 *
 * The Poly1305 tag covers encrypted_length || ciphertext.
 */
class ChaCha20Poly1305Cipher(key: ByteArray) : PacketAead {
    companion object {
        const val KEY_SIZE = 64
        const val TAG_SIZE = 16
        const val BLOCK_SIZE = 8
    }

    override val tagLength: Int = TAG_SIZE
    override val encryptsLength: Boolean = true

    private val mainKeySpec: SecretKeySpec
    private val headerKeySpec: SecretKeySpec

    private val headerCipher: Cipher
    private val polyKeyCipher: Cipher
    private val payloadCipher: Cipher

    private val poly = Poly1305()

    private val nonce = ByteArray(12)
    private val polyKeyZeros = ByteArray(32)
    private val polyKey = ByteArray(32)
    private val computedTag = ByteArray(TAG_SIZE)
    private val skipToNextBlock = ByteArray(64)

    init {
        require(key.size == KEY_SIZE) { "ChaCha20-Poly1305 requires 64 bytes of key material" }

        mainKeySpec = SecretKeySpec(key, 0, 32, "ChaCha20")
        headerKeySpec = SecretKeySpec(key, 32, 32, "ChaCha20")

        headerCipher = Cipher.getInstance("ChaCha20")
        polyKeyCipher = Cipher.getInstance("ChaCha20")
        payloadCipher = Cipher.getInstance("ChaCha20")
    }

    private fun updateNonce(seqNum: Long) {
        nonce[8] = (seqNum ushr 24).toByte()
        nonce[9] = (seqNum ushr 16).toByte()
        nonce[10] = (seqNum ushr 8).toByte()
        nonce[11] = seqNum.toByte()
    }

    override fun encryptLength(sequenceNumber: Long, plainLength: ByteArray): ByteArray {
        updateNonce(sequenceNumber)
        val params = ChaCha20ParamFactory.create(nonce, 0)
        headerCipher.init(Cipher.ENCRYPT_MODE, headerKeySpec, params)
        val dest = ByteArray(4)
        headerCipher.doFinal(plainLength, 0, 4, dest, 0)
        return dest
    }

    override fun decryptLength(sequenceNumber: Long, encryptedLength: ByteArray): ByteArray {
        updateNonce(sequenceNumber)
        val params = ChaCha20ParamFactory.create(nonce, 0)
        headerCipher.init(Cipher.DECRYPT_MODE, headerKeySpec, params)
        val dest = ByteArray(4)
        headerCipher.doFinal(encryptedLength, 0, 4, dest, 0)
        return dest
    }

    override fun encrypt(packetLength: ByteArray, plaintext: ByteArray): AeadResult {
        // Note: nonce already set by encryptLength() for the same sequence number
        val ciphertext = ByteArray(plaintext.size)
        val tag = ByteArray(TAG_SIZE)

        if (ChaCha20ParamFactory.usesChaCha20ParameterSpec()) {
            val polyKeyParams = ChaCha20ParamFactory.create(nonce, 0)
            polyKeyCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, polyKeyParams)
            polyKeyCipher.doFinal(polyKeyZeros, 0, 32, polyKey, 0)

            val payloadParams = ChaCha20ParamFactory.create(nonce, 1)
            payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, payloadParams)
            payloadCipher.doFinal(plaintext, 0, plaintext.size, ciphertext, 0)
        } else {
            val params = ChaCha20ParamFactory.create(nonce, 0)
            payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, params)
            payloadCipher.update(polyKeyZeros, 0, 32, polyKey, 0)
            payloadCipher.update(skipToNextBlock, 0, 32, skipToNextBlock, 0)
            payloadCipher.doFinal(plaintext, 0, plaintext.size, ciphertext, 0)
        }

        poly.init(polyKey)
        poly.update(packetLength, 0, 4)
        poly.update(ciphertext, 0, ciphertext.size)
        poly.finish(tag, 0)

        polyKey.fill(0)

        return AeadResult(ciphertext, tag)
    }

    override fun decrypt(packetLength: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray {
        // Note: nonce already set by decryptLength() for the same sequence number
        if (ChaCha20ParamFactory.usesChaCha20ParameterSpec()) {
            val polyKeyParams = ChaCha20ParamFactory.create(nonce, 0)
            polyKeyCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, polyKeyParams)
            polyKeyCipher.doFinal(polyKeyZeros, 0, 32, polyKey, 0)
        } else {
            val params = ChaCha20ParamFactory.create(nonce, 0)
            payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, params)
            payloadCipher.update(polyKeyZeros, 0, 32, polyKey, 0)
        }

        poly.init(polyKey)
        poly.update(packetLength, 0, 4)
        poly.update(ciphertext, 0, ciphertext.size)
        poly.finish(computedTag, 0)

        val tagValid = constantTimeEquals(tag, computedTag)
        computedTag.fill(0)
        polyKey.fill(0)

        if (!tagValid) {
            throw TransportException("ChaCha20-Poly1305 authentication failed")
        }

        val plaintext = ByteArray(ciphertext.size)
        if (ChaCha20ParamFactory.usesChaCha20ParameterSpec()) {
            val payloadParams = ChaCha20ParamFactory.create(nonce, 1)
            payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, payloadParams)
            payloadCipher.doFinal(ciphertext, 0, ciphertext.size, plaintext, 0)
        } else {
            // For IvParameterSpec path, cipher was already initialized in polyKey generation
            payloadCipher.update(skipToNextBlock, 0, 32, skipToNextBlock, 0)
            payloadCipher.doFinal(ciphertext, 0, ciphertext.size, plaintext, 0)
        }

        return plaintext
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }
}
