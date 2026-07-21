/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** PBES2 encrypted PKCS#8 using PBKDF2-HMAC-SHA256 and AES-256-CBC. */
internal object Pkcs8Encryption {
    private const val ITERATIONS = 210_000
    private const val MAX_ITERATIONS = 10_000_000
    private const val KEY_BITS = 256
    private const val KEY_BYTES = KEY_BITS / Byte.SIZE_BITS
    private const val SALT_BYTES = 16
    private const val IV_BYTES = 16

    private val oidPbes2 = oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D)
    private val oidPbkdf2 = oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C)
    private val oidHmacSha256 = oid(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09)
    private val oidAes256Cbc = oid(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A)

    fun encrypt(plaintext: ByteArray, password: String, random: SecureRandom = SecureRandom()): ByteArray {
        val salt = ByteArray(SALT_BYTES).also(random::nextBytes)
        val iv = ByteArray(IV_BYTES).also(random::nextBytes)
        val ciphertext = crypt(Cipher.ENCRYPT_MODE, plaintext, password, salt, ITERATIONS, iv)

        return encodeDer {
            sequence {
                sequence {
                    objectIdentifier(oidPbes2)
                    sequence {
                        sequence {
                            objectIdentifier(oidPbkdf2)
                            sequence {
                                octetString(salt)
                                integer(BigInteger.valueOf(ITERATIONS.toLong()))
                                integer(BigInteger.valueOf(KEY_BYTES.toLong()))
                                sequence {
                                    objectIdentifier(oidHmacSha256)
                                    nullValue()
                                }
                            }
                        }
                        sequence {
                            objectIdentifier(oidAes256Cbc)
                            octetString(iv)
                        }
                    }
                }
                octetString(ciphertext)
            }
        }
    }

    fun decrypt(encoded: ByteArray, password: String): ByteArray {
        val reader = DerReader(encoded)
        val parsed = reader.readSequence { outer ->
            val parameters = outer.readSequence { algorithm ->
                requireOid(algorithm.readObjectIdentifier(), oidPbes2, "PBES2")
                algorithm.readSequence { pbes2 ->
                    val kdf = pbes2.readSequence { keyDerivation ->
                        requireOid(keyDerivation.readObjectIdentifier(), oidPbkdf2, "PBKDF2")
                        keyDerivation.readSequence { pbkdf2 ->
                            val salt = pbkdf2.readOctetString()
                            val iterations = positiveInt(pbkdf2.readInteger(), "PBKDF2 iteration count")
                            if (iterations > MAX_ITERATIONS) {
                                throw SshException("PBKDF2 iteration count exceeds supported maximum")
                            }
                            val keyLength = if (pbkdf2.peekTag() == 0x02) {
                                positiveInt(pbkdf2.readInteger(), "PBKDF2 key length")
                            } else {
                                KEY_BYTES
                            }
                            if (keyLength != KEY_BYTES) {
                                throw SshException("Unsupported PBKDF2 key length: $keyLength")
                            }
                            pbkdf2.readSequence { prf ->
                                requireOid(prf.readObjectIdentifier(), oidHmacSha256, "HMAC-SHA256")
                                if (prf.hasRemaining()) prf.skipTag()
                            }
                            KdfParameters(salt, iterations)
                        }
                    }
                    val iv = pbes2.readSequence { encryptionScheme ->
                        requireOid(encryptionScheme.readObjectIdentifier(), oidAes256Cbc, "AES-256-CBC")
                        encryptionScheme.readOctetString()
                    }
                    if (iv.size != IV_BYTES) throw SshException("Invalid AES-256-CBC IV length: ${iv.size}")
                    EncryptionParameters(kdf.salt, kdf.iterations, iv)
                }
            }
            ParsedEncryptedKey(parameters, outer.readOctetString())
        }
        reader.ensureFullyConsumed()

        return crypt(
            Cipher.DECRYPT_MODE,
            parsed.ciphertext,
            password,
            parsed.parameters.salt,
            parsed.parameters.iterations,
            parsed.parameters.iv,
        )
    }

    private fun crypt(
        mode: Int,
        input: ByteArray,
        password: String,
        salt: ByteArray,
        iterations: Int,
        iv: ByteArray,
    ): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_BITS)
        var keyBytes: ByteArray? = null
        try {
            keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(mode, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
            return cipher.doFinal(input)
        } catch (e: GeneralSecurityException) {
            throw SshException("Unable to process encrypted PKCS#8 private key", e)
        } finally {
            spec.clearPassword()
            keyBytes?.fill(0)
        }
    }

    private fun positiveInt(value: BigInteger, name: String): Int {
        if (value.signum() <= 0 || value.bitLength() > 31) throw SshException("Invalid $name")
        return value.toInt()
    }

    private fun requireOid(actual: ByteArray, expected: ByteArray, name: String) {
        if (!actual.contentEquals(expected)) throw SshException("Unsupported encrypted PKCS#8 algorithm; expected $name")
    }

    private fun oid(vararg bytes: Int): ByteArray = ByteArray(bytes.size) { bytes[it].toByte() }

    private data class KdfParameters(val salt: ByteArray, val iterations: Int)
    private data class EncryptionParameters(val salt: ByteArray, val iterations: Int, val iv: ByteArray)
    private data class ParsedEncryptedKey(val parameters: EncryptionParameters, val ciphertext: ByteArray)
}
