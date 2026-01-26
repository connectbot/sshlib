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

/**
 * Interface for SSH packet encryption/decryption.
 */
interface PacketCipher {
    /**
     * Block size in bytes for this cipher.
     */
    val blockSize: Int

    /**
     * Encrypt data.
     *
     * @param data Plaintext data (must be multiple of blockSize)
     * @return Encrypted data
     */
    fun encrypt(data: ByteArray): ByteArray

    /**
     * Decrypt data.
     *
     * @param data Encrypted data (must be multiple of blockSize)
     * @return Plaintext data
     */
    fun decrypt(data: ByteArray): ByteArray
}
