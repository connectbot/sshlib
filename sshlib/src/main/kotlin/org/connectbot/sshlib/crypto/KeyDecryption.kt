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
import org.mindrot.jbcrypt.BCrypt
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object KeyDecryption {

    fun decryptOpenSsh(
        data: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        rounds: Int,
        cipherName: String,
    ): ByteArray {
        val (jcaCipher, keySize, ivSize) = when (cipherName.lowercase()) {
            "aes256-ctr" -> Triple("AES/CTR/NoPadding", 32, 16)
            "aes256-cbc" -> Triple("AES/CBC/NoPadding", 32, 16)
            "aes128-ctr" -> Triple("AES/CTR/NoPadding", 16, 16)
            "aes128-cbc" -> Triple("AES/CBC/NoPadding", 16, 16)
            "aes192-ctr" -> Triple("AES/CTR/NoPadding", 24, 16)
            "aes192-cbc" -> Triple("AES/CBC/NoPadding", 24, 16)
            else -> throw SshException("Unsupported OpenSSH cipher: $cipherName")
        }

        val keyAndIv = ByteArray(keySize + ivSize)
        BCrypt().pbkdf(password, salt, rounds, keyAndIv)

        val key = keyAndIv.copyOfRange(0, keySize)
        val iv = keyAndIv.copyOfRange(keySize, keySize + ivSize)

        val cipher = Cipher.getInstance(jcaCipher)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun decryptPem(
        data: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        cipherName: String,
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

        val key = generateKeyFromPasswordSaltWithMD5(password, salt, keySize)
        val cipher = Cipher.getInstance(jcaCipher)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, keyAlgorithm), IvParameterSpec(salt))
        val decrypted = cipher.doFinal(data)

        return removePkcs7Padding(decrypted, cipher.blockSize)
    }

    private fun removePkcs7Padding(data: ByteArray, blockSize: Int): ByteArray {
        val padding = data[data.size - 1].toInt() and 0xFF
        if (padding < 1 || padding > blockSize) {
            throw SshException("Decrypted block has wrong padding, did you specify the correct password?")
        }
        for (i in 2..padding) {
            if ((data[data.size - i].toInt() and 0xFF) != padding) {
                throw SshException("Decrypted block has wrong padding, did you specify the correct password?")
            }
        }
        return data.copyOfRange(0, data.size - padding)
    }

    internal fun generateKeyFromPasswordSaltWithMD5(
        password: ByteArray,
        salt: ByteArray,
        keyLen: Int,
    ): ByteArray {
        val md5 = MessageDigest.getInstance("MD5")
        val key = ByteArray(keyLen)
        var remaining = keyLen
        var offset = 0
        var previousHash: ByteArray? = null

        while (remaining > 0) {
            if (previousHash != null) {
                md5.update(previousHash)
            }
            md5.update(password)
            md5.update(salt, 0, minOf(8, salt.size))
            previousHash = md5.digest()

            val copy = minOf(remaining, previousHash.size)
            System.arraycopy(previousHash, 0, key, offset, copy)
            offset += copy
            remaining -= copy
        }

        return key
    }

    fun hexToByteArray(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Uneven string length in hex encoding" }
        return ByteArray(hex.length / 2) { i ->
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            ((hi shl 4) or lo).toByte()
        }
    }
}
