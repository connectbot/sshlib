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

import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.XECPrivateKeySpec
import javax.crypto.KeyAgreement

internal class PlatformX25519Provider : X25519Provider {
    companion object {
        private const val ALGORITHM = "X25519"

        private val PKCS8_PREFIX = byteArrayOf(
            0x30, 0x2e, // SEQUENCE (46 bytes)
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, // SEQUENCE (5 bytes)
            0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
            0x04, 0x22, // OCTET STRING (34 bytes)
            0x04, 0x20, // OCTET STRING (32 bytes)
        )

        private val X509_PREFIX = byteArrayOf(
            0x30, 0x2a, // SEQUENCE (42 bytes)
            0x30, 0x05, // SEQUENCE (5 bytes)
            0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
            0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused bits)
        )

        private val BASE_POINT = ByteArray(X25519Provider.KEY_SIZE).apply { this[0] = 9 }
    }

    private val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
    private val keyFactory = KeyFactory.getInstance(ALGORITHM)

    override fun generatePrivateKey(): ByteArray {
        val keyPair = keyPairGenerator.generateKeyPair()
        return extractPrivateKeyBytes(keyPair.private)
    }

    override fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        val privKey = createPrivateKey(privateKey)
        val ka = KeyAgreement.getInstance(ALGORITHM)
        ka.init(privKey)
        ka.doPhase(createPublicKey(BASE_POINT), true)
        return ka.generateSecret()
    }

    override fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val privKey = createPrivateKey(privateKey)
        val pubKey = createPublicKey(publicKey)
        val ka = KeyAgreement.getInstance(ALGORITHM)
        ka.init(privKey)
        ka.doPhase(pubKey, true)
        return ka.generateSecret()
    }

    private fun createPrivateKey(keyBytes: ByteArray): PrivateKey {
        val pkcs8 = ByteArray(PKCS8_PREFIX.size + X25519Provider.KEY_SIZE)
        System.arraycopy(PKCS8_PREFIX, 0, pkcs8, 0, PKCS8_PREFIX.size)
        System.arraycopy(keyBytes, 0, pkcs8, PKCS8_PREFIX.size, X25519Provider.KEY_SIZE)
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
    }

    private fun createPublicKey(keyBytes: ByteArray): PublicKey {
        val x509 = ByteArray(X509_PREFIX.size + X25519Provider.KEY_SIZE)
        System.arraycopy(X509_PREFIX, 0, x509, 0, X509_PREFIX.size)
        System.arraycopy(keyBytes, 0, x509, X509_PREFIX.size, X25519Provider.KEY_SIZE)
        return keyFactory.generatePublic(X509EncodedKeySpec(x509))
    }

    private fun extractPrivateKeyBytes(privateKey: PrivateKey): ByteArray {
        val spec = keyFactory.getKeySpec(privateKey, XECPrivateKeySpec::class.java)
        val scalar = spec.scalar
        if (scalar.size == X25519Provider.KEY_SIZE) return scalar
        val padded = ByteArray(X25519Provider.KEY_SIZE)
        System.arraycopy(scalar, 0, padded, X25519Provider.KEY_SIZE - scalar.size, scalar.size)
        return padded
    }
}
