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

internal object PrivateKeyReader {

    fun read(keyData: ByteArray, passphrase: String? = null): SshPrivateKey = read(String(keyData, Charsets.UTF_8), passphrase)

    fun read(keyData: String, passphrase: String? = null): SshPrivateKey {
        val trimmed = keyData.trim()
        return when {
            trimmed.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----") -> {
                val base64 = extractBase64(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----")
                val data = Base64Compat.decode(base64)
                OpenSshKeyReader.read(data, passphrase)
            }

            trimmed.startsWith("-----BEGIN RSA PRIVATE KEY-----") ||
                trimmed.startsWith("-----BEGIN EC PRIVATE KEY-----") ||
                trimmed.startsWith("-----BEGIN PRIVATE KEY-----") -> {
                PemKeyReader.read(trimmed, passphrase)
            }

            else -> throw SshException("Unrecognized private key format")
        }
    }

    fun isEncrypted(keyData: ByteArray): Boolean = isEncrypted(String(keyData, Charsets.UTF_8))

    fun isEncrypted(keyData: String): Boolean {
        val trimmed = keyData.trim()
        return when {
            trimmed.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----") -> {
                val base64 = extractBase64(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----")
                val data = Base64Compat.decode(base64)
                OpenSshKeyReader.isEncrypted(data)
            }

            trimmed.startsWith("-----BEGIN RSA PRIVATE KEY-----") ||
                trimmed.startsWith("-----BEGIN EC PRIVATE KEY-----") -> {
                PemKeyReader.isEncrypted(trimmed)
            }

            trimmed.startsWith("-----BEGIN PRIVATE KEY-----") -> false

            // PKCS#8 unencrypted
            else -> throw SshException("Unrecognized private key format")
        }
    }

    private fun extractBase64(text: String, beginMarker: String, endMarker: String): String {
        val builder = StringBuilder()
        var inBody = false
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.startsWith(endMarker)) break
            if (inBody) {
                builder.append(trimmed)
            }
            if (trimmed.startsWith(beginMarker)) {
                inBody = true
            }
        }
        return builder.toString()
    }
}
