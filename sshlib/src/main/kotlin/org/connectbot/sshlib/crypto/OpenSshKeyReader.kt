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
import org.connectbot.sshlib.protocol.readByteString
import org.connectbot.sshlib.protocol.readMpintUnsigned
import org.connectbot.sshlib.protocol.readString
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec

internal object OpenSshKeyReader {

    private val OPENSSH_V1_MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)

    fun isEncrypted(data: ByteArray): Boolean {
        val buf = ByteBuffer.wrap(data)
        skipMagic(buf)
        buf.readString() // cipher name
        val kdfName = buf.readString()
        return kdfName != "none"
    }

    fun read(data: ByteArray, passphrase: String?): SshPrivateKey {
        val buf = ByteBuffer.wrap(data)
        skipMagic(buf)

        val cipherName = buf.readString()
        val kdfName = buf.readString()
        val kdfOptions = buf.readByteString()
        val numberOfKeys = buf.int

        if (numberOfKeys != 1) {
            throw SshException("Only one key supported, but encountered bundle of $numberOfKeys")
        }

        buf.readByteString() // public key blob (discarded)

        var privateSection = buf.readByteString()

        if (kdfName == "bcrypt") {
            if (passphrase == null) {
                throw SshException("OpenSSH key is encrypted but no passphrase provided")
            }
            val optBuf = ByteBuffer.wrap(kdfOptions)
            val salt = optBuf.readByteString()
            val rounds = optBuf.int
            val passwordBytes = passphrase.toByteArray(Charsets.UTF_8)
            privateSection = KeyDecryption.decryptOpenSsh(privateSection, passwordBytes, salt, rounds, cipherName)
        } else if (cipherName != "none" || kdfName != "none") {
            throw SshException("Unsupported encryption: cipher=$cipherName, kdf=$kdfName")
        }

        val priv = ByteBuffer.wrap(privateSection)
        val checkInt1 = priv.int
        val checkInt2 = priv.int

        if (checkInt1 != checkInt2) {
            throw SshException("Decryption failed (check integers don't match)")
        }

        val keyType = priv.readString()

        val keyPair: KeyPair
        val sigAlgorithm: String

        when {
            keyType == "ssh-ed25519" -> {
                priv.readByteString() // public key (64 bytes but we only need the seed)
                val privateBytes = priv.readByteString() // 64 bytes: seed || public
                val seed = privateBytes.copyOfRange(0, 32)

                val pkcs8 = encodeDer {
                    sequence {
                        integer(BigInteger.ZERO)
                        sequence {
                            objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70)) // 1.3.101.112
                        }
                        octetString(encodeDer { octetString(seed) })
                    }
                }
                val privKey = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(PKCS8EncodedKeySpec(pkcs8))

                val pubKeyBytes = privateBytes.copyOfRange(32, 64)
                val x509 = encodeDer {
                    sequence {
                        sequence {
                            objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70))
                        }
                        bitString(pubKeyBytes)
                    }
                }
                val pubKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(X509EncodedKeySpec(x509))

                keyPair = KeyPair(pubKey, privKey)
                sigAlgorithm = "ssh-ed25519"
            }

            keyType.startsWith("ecdsa-sha2-") -> {
                val curveName = priv.readString()
                val qBytes = priv.readByteString() // public point (uncompressed)
                val privateScalar = priv.readMpintUnsigned()

                val (ecGenSpec, sshAlg) = when (curveName) {
                    "nistp256" -> ECGenParameterSpec("secp256r1") to "ecdsa-sha2-nistp256"
                    "nistp384" -> ECGenParameterSpec("secp384r1") to "ecdsa-sha2-nistp384"
                    "nistp521" -> ECGenParameterSpec("secp521r1") to "ecdsa-sha2-nistp521"
                    else -> throw SshException("Unknown EC curve: $curveName")
                }

                val params = AlgorithmParameters.getInstance("EC")
                params.init(ecGenSpec)
                val paramSpec = params.getParameterSpec(ECParameterSpec::class.java)

                val point = EcdsaSignatureAlgorithm.decodeEcPoint(qBytes, paramSpec)
                val pubKeySpec = ECPublicKeySpec(point, paramSpec)
                val privKeySpec = ECPrivateKeySpec(privateScalar, paramSpec)

                val kf = KeyFactory.getInstance("EC")
                keyPair = KeyPair(kf.generatePublic(pubKeySpec), kf.generatePrivate(privKeySpec))
                sigAlgorithm = sshAlg
            }

            keyType == "ssh-rsa" -> {
                val n = priv.readMpintUnsigned()
                val e = priv.readMpintUnsigned()
                val d = priv.readMpintUnsigned()
                val iqmp = priv.readMpintUnsigned()
                val p = priv.readMpintUnsigned()
                val q = priv.readMpintUnsigned()

                val dP = d.mod(p.subtract(BigInteger.ONE))
                val dQ = d.mod(q.subtract(BigInteger.ONE))

                val privKeySpec = RSAPrivateCrtKeySpec(n, e, d, p, q, dP, dQ, iqmp)
                val pubKeySpec = RSAPublicKeySpec(n, e)

                val kf = KeyFactory.getInstance("RSA")
                keyPair = KeyPair(kf.generatePublic(pubKeySpec), kf.generatePrivate(privKeySpec))
                sigAlgorithm = "rsa-sha2-512"
            }

            else -> throw SshException("Unknown key type: $keyType")
        }

        // Also read the comment string that trails the key material
        priv.readString()

        // Validate padding: remaining bytes must be 1, 2, 3, ... (mod 256)
        var padByte = 1
        while (priv.hasRemaining()) {
            val b = priv.get().toInt() and 0xff
            if (b != padByte and 0xff) {
                throw SshException("Invalid OpenSSH key padding at byte $padByte")
            }
            padByte++
        }

        return SshPrivateKey(keyType, keyPair, sigAlgorithm)
    }

    private fun skipMagic(buf: ByteBuffer) {
        val magic = ByteArray(OPENSSH_V1_MAGIC.size)
        buf.get(magic)
        if (!magic.contentEquals(OPENSSH_V1_MAGIC)) {
            throw SshException("Invalid OpenSSH key magic")
        }
    }
}
