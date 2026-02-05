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
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

internal object SshPublicKeyEncoder {

    fun encode(keyPair: KeyPair, keyType: String): ByteArray {
        return when {
            keyType == "ssh-ed25519" -> encodeEd25519(keyPair)
            keyType.startsWith("ecdsa-sha2-") -> encodeEcdsa(keyPair, keyType)
            keyType == "ssh-rsa" -> encodeRsa(keyPair)
            else -> throw SshException("Unsupported key type for encoding: $keyType")
        }
    }

    private fun encodeEd25519(keyPair: KeyPair): ByteArray {
        val pubKeyEncoded = keyPair.public.encoded
        // X.509 Ed25519 public key: the last 32 bytes are the raw key
        val rawKey = pubKeyEncoded.copyOfRange(pubKeyEncoded.size - 32, pubKeyEncoded.size)

        return encodeSshString("ssh-ed25519".toByteArray(Charsets.US_ASCII)) +
                encodeSshString(rawKey)
    }

    private fun encodeEcdsa(keyPair: KeyPair, keyType: String): ByteArray {
        val ecPub = keyPair.public as ECPublicKey
        val curveName = when (keyType) {
            "ecdsa-sha2-nistp256" -> "nistp256"
            "ecdsa-sha2-nistp384" -> "nistp384"
            "ecdsa-sha2-nistp521" -> "nistp521"
            else -> throw SshException("Unknown ECDSA key type: $keyType")
        }

        val fieldSize = (ecPub.params.order.bitLength() + 7) / 8
        val qBytes = encodeEcPoint(ecPub, fieldSize)

        return encodeSshString(keyType.toByteArray(Charsets.US_ASCII)) +
                encodeSshString(curveName.toByteArray(Charsets.US_ASCII)) +
                encodeSshString(qBytes)
    }

    private fun encodeEcPoint(pubKey: ECPublicKey, fieldSize: Int): ByteArray {
        val point = pubKey.w
        val xBytes = point.affineX.toByteArray().let { padOrTrim(it, fieldSize) }
        val yBytes = point.affineY.toByteArray().let { padOrTrim(it, fieldSize) }

        val result = ByteArray(1 + 2 * fieldSize)
        result[0] = 0x04 // uncompressed
        System.arraycopy(xBytes, 0, result, 1, fieldSize)
        System.arraycopy(yBytes, 0, result, 1 + fieldSize, fieldSize)
        return result
    }

    private fun padOrTrim(bytes: ByteArray, size: Int): ByteArray {
        return when {
            bytes.size == size -> bytes
            bytes.size > size -> {
                // Strip leading zeros
                val start = bytes.size - size
                bytes.copyOfRange(start, bytes.size)
            }
            else -> {
                // Pad with leading zeros
                val result = ByteArray(size)
                System.arraycopy(bytes, 0, result, size - bytes.size, bytes.size)
                result
            }
        }
    }

    private fun encodeRsa(keyPair: KeyPair): ByteArray {
        val rsaPub = keyPair.public as RSAPublicKey

        return encodeSshString("ssh-rsa".toByteArray(Charsets.US_ASCII)) +
                encodeMpint(rsaPub.publicExponent.toByteArray()) +
                encodeMpint(rsaPub.modulus.toByteArray())
    }
}
