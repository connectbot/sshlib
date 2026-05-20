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
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPrivateKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey

internal object OpenSshKeyWriter {

    private val OPENSSH_V1_MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)
    private const val LINE_LENGTH = 70
    private const val DEFAULT_ROUNDS = 16

    fun write(keyPair: KeyPair, password: String? = null): String {
        val keyType = inferKeyType(keyPair)
        val publicKeyBlob = SshPublicKeyEncoder.encode(keyPair, keyType)

        val privateSection = buildPrivateSection(keyPair, keyType, password != null)

        val encrypted: Boolean
        val cipherName: String
        val kdfName: String
        val kdfOptions: ByteArray
        val encryptedSection: ByteArray

        if (password != null) {
            encrypted = true
            cipherName = "aes256-ctr"
            kdfName = "bcrypt"
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            kdfOptions = encodeSshString(salt) + encodeUint32(DEFAULT_ROUNDS)
            encryptedSection = KeyEncryption.encryptOpenSsh(
                privateSection,
                password.toByteArray(Charsets.UTF_8),
                salt,
                DEFAULT_ROUNDS,
                cipherName,
            )
        } else {
            encrypted = false
            cipherName = "none"
            kdfName = "none"
            kdfOptions = ByteArray(0)
            encryptedSection = privateSection
        }

        val binaryData = buildBinaryData(
            cipherName,
            kdfName,
            kdfOptions,
            publicKeyBlob,
            encryptedSection,
        )

        return formatOutput(binaryData)
    }

    private fun buildBinaryData(
        cipherName: String,
        kdfName: String,
        kdfOptions: ByteArray,
        publicKeyBlob: ByteArray,
        encryptedSection: ByteArray,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(OPENSSH_V1_MAGIC)
        out.write(encodeSshString(cipherName.toByteArray(Charsets.US_ASCII)))
        out.write(encodeSshString(kdfName.toByteArray(Charsets.US_ASCII)))
        out.write(encodeSshString(kdfOptions))
        out.write(encodeUint32(1)) // number of keys
        out.write(encodeSshString(publicKeyBlob))
        out.write(encodeSshString(encryptedSection))
        return out.toByteArray()
    }

    private fun buildPrivateSection(keyPair: KeyPair, keyType: String, encrypted: Boolean): ByteArray {
        val checkInt = SecureRandom().nextInt()
        val out = ByteArrayOutputStream()

        out.write(encodeUint32(checkInt))
        out.write(encodeUint32(checkInt))

        when {
            keyType == "ssh-ed25519" -> writeEd25519Private(out, keyPair)
            keyType.startsWith("ecdsa-sha2-") -> writeEcdsaPrivate(out, keyPair, keyType)
            keyType == "ssh-rsa" -> writeRsaPrivate(out, keyPair)
            else -> throw SshException("Unsupported key type for OpenSSH encoding: $keyType")
        }

        // Empty comment
        out.write(encodeSshString(ByteArray(0)))

        // Add padding
        val blockSize = if (encrypted) 16 else 8
        val currentSize = out.size()
        val paddingNeeded = (blockSize - (currentSize % blockSize)) % blockSize
        for (i in 1..paddingNeeded) {
            out.write(i and 0xFF)
        }

        return out.toByteArray()
    }

    private fun writeEd25519Private(out: ByteArrayOutputStream, keyPair: KeyPair) {
        out.write(encodeSshString("ssh-ed25519".toByteArray(Charsets.US_ASCII)))

        // Extract raw 32-byte public key from X.509 encoding
        val pubEncoded = keyPair.public.encoded
        val pubKey32 = pubEncoded.copyOfRange(pubEncoded.size - 32, pubEncoded.size)

        out.write(encodeSshString(pubKey32))

        // Extract seed from the private key
        val seed = extractEd25519Seed(keyPair)

        // Private section: seed || public (64 bytes)
        val privBytes = ByteArray(64)
        System.arraycopy(seed, 0, privBytes, 0, 32)
        System.arraycopy(pubKey32, 0, privBytes, 32, 32)
        out.write(encodeSshString(privBytes))
    }

    private fun extractEd25519Seed(keyPair: KeyPair): ByteArray {
        val privKey = keyPair.private
        return when {
            privKey is EdECPrivateKey -> {
                privKey.bytes.orElseThrow { SshException("Cannot extract Ed25519 seed") }
            }

            privKey.javaClass.name.contains("Ed25519PrivateKey") -> {
                // Our Ed25519PrivateKey or similar — extract from PKCS#8 encoding
                val encoded = privKey.encoded
                val reader = DerReader(encoded)
                reader.readSequence { seq ->
                    seq.readInteger() // version
                    seq.readSequence { algId -> while (algId.hasRemaining()) algId.skipTag() }
                    val innerBytes = seq.readOctetString()
                    val innerReader = DerReader(innerBytes)
                    innerReader.readOctetString()
                }
            }

            else -> throw SshException("Cannot extract Ed25519 seed from ${privKey.javaClass}")
        }
    }

    private fun writeEcdsaPrivate(out: ByteArrayOutputStream, keyPair: KeyPair, keyType: String) {
        out.write(encodeSshString(keyType.toByteArray(Charsets.US_ASCII)))

        val ecPub = keyPair.public as ECPublicKey
        val ecPriv = keyPair.private as ECPrivateKey

        val curveName = when (keyType) {
            "ecdsa-sha2-nistp256" -> "nistp256"
            "ecdsa-sha2-nistp384" -> "nistp384"
            "ecdsa-sha2-nistp521" -> "nistp521"
            else -> throw SshException("Unknown ECDSA key type: $keyType")
        }

        val fieldSize = (ecPub.params.order.bitLength() + 7) / 8
        val qBytes = SshPublicKeyEncoder.encodeEcPoint(ecPub, fieldSize)

        out.write(encodeSshString(curveName.toByteArray(Charsets.US_ASCII)))
        out.write(encodeSshString(qBytes))
        out.write(encodeMpint(ecPriv.s.toByteArray()))
    }

    private fun writeRsaPrivate(out: ByteArrayOutputStream, keyPair: KeyPair) {
        out.write(encodeSshString("ssh-rsa".toByteArray(Charsets.US_ASCII)))

        val rsaPriv = keyPair.private as RSAPrivateCrtKey

        out.write(encodeMpint(rsaPriv.modulus.toByteArray()))
        out.write(encodeMpint(rsaPriv.publicExponent.toByteArray()))
        out.write(encodeMpint(rsaPriv.privateExponent.toByteArray()))
        out.write(encodeMpint(rsaPriv.crtCoefficient.toByteArray()))
        out.write(encodeMpint(rsaPriv.primeP.toByteArray()))
        out.write(encodeMpint(rsaPriv.primeQ.toByteArray()))
    }

    private fun encodeUint32(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun formatOutput(data: ByteArray): String {
        val sb = StringBuilder()
        sb.appendLine("-----BEGIN OPENSSH PRIVATE KEY-----")
        val base64 = Base64Compat.encodeWithPadding(data)
        sb.appendLine(base64.chunked(LINE_LENGTH).joinToString("\n"))
        sb.appendLine("-----END OPENSSH PRIVATE KEY-----")
        return sb.toString()
    }
}
