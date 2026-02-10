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
import org.mindrot.jbcrypt.BCrypt
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object KeyEncryption {

    fun encryptPem(
        data: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        cipherName: String
    ): ByteArray {
        val (jcaCipher, keySize) = when (cipherName.uppercase()) {
            "DES-EDE3-CBC" -> "DESede/CBC/NoPadding" to 24
            "DES-CBC" -> "DES/CBC/NoPadding" to 8
            "AES-128-CBC" -> "AES/CBC/NoPadding" to 16
            "AES-192-CBC" -> "AES/CBC/NoPadding" to 24
            "AES-256-CBC" -> "AES/CBC/NoPadding" to 32
            else -> throw SshException("Unsupported PEM cipher: $cipherName")
        }

        val keyAlgorithm = when {
            jcaCipher.startsWith("DESede") -> "DESede"
            jcaCipher.startsWith("DES") -> "DES"
            else -> "AES"
        }

        val blockSize = when {
            jcaCipher.startsWith("DES") -> 8
            else -> 16
        }

        val padded = addPkcs7Padding(data, blockSize)
        val key = KeyDecryption.generateKeyFromPasswordSaltWithMD5(password, salt, keySize)
        val cipher = Cipher.getInstance(jcaCipher)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, keyAlgorithm), IvParameterSpec(salt))
        return cipher.doFinal(padded)
    }

    fun encryptOpenSsh(
        data: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        rounds: Int,
        cipherName: String
    ): ByteArray {
        val (jcaCipher, keySize, ivSize) = when (cipherName.lowercase()) {
            "aes256-ctr" -> Triple("AES/CTR/NoPadding", 32, 16)
            "aes256-cbc" -> Triple("AES/CBC/NoPadding", 32, 16)
            "aes128-ctr" -> Triple("AES/CTR/NoPadding", 16, 16)
            "aes128-cbc" -> Triple("AES/CBC/NoPadding", 16, 16)
            else -> throw SshException("Unsupported OpenSSH cipher: $cipherName")
        }

        val keyAndIv = ByteArray(keySize + ivSize)
        BCrypt().pbkdf(password, salt, rounds, keyAndIv)

        val key = keyAndIv.copyOfRange(0, keySize)
        val iv = keyAndIv.copyOfRange(keySize, keySize + ivSize)

        val cipher = Cipher.getInstance(jcaCipher)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun addPkcs7Padding(data: ByteArray, blockSize: Int): ByteArray {
        val padding = blockSize - (data.size % blockSize)
        val padded = ByteArray(data.size + padding)
        System.arraycopy(data, 0, padded, 0, data.size)
        for (i in data.size until padded.size) {
            padded[i] = padding.toByte()
        }
        return padded
    }

    fun byteArrayToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02X".format(it) }
    }
}
