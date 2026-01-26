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

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-CTR cipher implementation for SSH packet encryption/decryption.
 *
 * Supports AES-128-CTR and AES-256-CTR as specified in RFC 4344.
 *
 * Note: Each instance should be used for only one direction (encrypt OR decrypt).
 * CTR mode maintains internal counter state across multiple packets.
 *
 * @param key Encryption key (16 or 32 bytes for AES-128 or AES-256)
 * @param iv Initial counter value (16 bytes)
 * @param forEncryption True for encryption, false for decryption
 */
class AesCtrCipher(
    private val key: ByteArray,
    private val iv: ByteArray,
    forEncryption: Boolean
) : PacketCipher {
    override val blockSize: Int = 16

    private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding")

    init {
        require(key.size == 16 || key.size == 32) {
            "AES key must be 16 or 32 bytes, got ${key.size}"
        }
        require(iv.size == 16) {
            "IV must be 16 bytes, got ${iv.size}"
        }

        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(iv)
        val mode = if (forEncryption) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
        cipher.init(mode, keySpec, ivSpec)
    }

    override fun encrypt(data: ByteArray): ByteArray {
        return cipher.update(data)
    }

    override fun decrypt(data: ByteArray): ByteArray {
        return cipher.update(data)
    }
}
