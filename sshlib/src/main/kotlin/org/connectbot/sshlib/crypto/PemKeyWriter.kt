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
import java.math.BigInteger
import java.security.KeyPair
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey

internal object PemKeyWriter {

    private const val LINE_LENGTH = 64

    fun write(keyPair: KeyPair, password: String? = null): String {
        val keyType = inferKeyType(keyPair)
        return when {
            keyType == "ssh-rsa" -> writeRsa(keyPair, password)
            keyType.startsWith("ecdsa-sha2-") -> writeEc(keyPair, password)
            keyType == "ssh-ed25519" -> writeEd25519(keyPair, password)
            else -> throw SshException("Unsupported key type for PEM encoding: $keyType")
        }
    }

    private fun writeRsa(keyPair: KeyPair, password: String?): String {
        val privKey = keyPair.private as RSAPrivateCrtKey
        val der = encodeDer {
            sequence {
                integer(BigInteger.ZERO) // version
                integer(privKey.modulus)
                integer(privKey.publicExponent)
                integer(privKey.privateExponent)
                integer(privKey.primeP)
                integer(privKey.primeQ)
                integer(privKey.primeExponentP)
                integer(privKey.primeExponentQ)
                integer(privKey.crtCoefficient)
            }
        }
        return wrapPem("RSA PRIVATE KEY", der, password)
    }

    private fun writeEc(keyPair: KeyPair, password: String?): String {
        val privKey = keyPair.private as ECPrivateKey
        val pubKey = keyPair.public as ECPublicKey

        val fieldSize = (privKey.params.order.bitLength() + 7) / 8
        val curveOid = when (fieldSize) {
            32 -> PemKeyReader.SECP256R1_OID
            48 -> PemKeyReader.SECP384R1_OID
            66 -> PemKeyReader.SECP521R1_OID
            else -> throw SshException("Unsupported EC field size: $fieldSize")
        }

        val privateBytes = privKey.s.toByteArray().let { bytes ->
            // Strip leading zero byte if present (BigInteger sign bit)
            if (bytes.size > fieldSize && bytes[0] == 0.toByte()) {
                bytes.copyOfRange(1, bytes.size)
            } else if (bytes.size < fieldSize) {
                // Pad with leading zeros
                val padded = ByteArray(fieldSize)
                System.arraycopy(bytes, 0, padded, fieldSize - bytes.size, bytes.size)
                padded
            } else {
                bytes
            }
        }

        val qBytes = SshPublicKeyEncoder.encodeEcPoint(pubKey, fieldSize)

        val der = encodeDer {
            sequence {
                integer(BigInteger.ONE) // version
                octetString(privateBytes)
                contextTag(0) {
                    objectIdentifier(curveOid)
                }
                contextTag(1) {
                    bitString(qBytes)
                }
            }
        }
        return wrapPem("EC PRIVATE KEY", der, password)
    }

    private fun writeEd25519(keyPair: KeyPair, password: String?): String {
        val der = keyPair.private.encoded
        return wrapPem("PRIVATE KEY", der, password)
    }

    private fun wrapPem(label: String, data: ByteArray, password: String?): String {
        val sb = StringBuilder()

        if (password != null && label != "PRIVATE KEY") {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            val cipherName = "AES-256-CBC"
            val encrypted = KeyEncryption.encryptPem(
                data,
                password.toByteArray(Charsets.ISO_8859_1),
                salt,
                cipherName
            )
            val saltHex = KeyEncryption.byteArrayToHex(salt)

            sb.appendLine("-----BEGIN $label-----")
            sb.appendLine("Proc-Type: 4,ENCRYPTED")
            sb.appendLine("DEK-Info: $cipherName,$saltHex")
            sb.appendLine()
            sb.appendLine(wrapBase64(encrypted))
            sb.appendLine("-----END $label-----")
        } else {
            sb.appendLine("-----BEGIN $label-----")
            sb.appendLine(wrapBase64(data))
            sb.appendLine("-----END $label-----")
        }

        return sb.toString()
    }

    private fun wrapBase64(data: ByteArray): String {
        val base64 = Base64Compat.encodeWithPadding(data)
        return base64.chunked(LINE_LENGTH).joinToString("\n")
    }
}
