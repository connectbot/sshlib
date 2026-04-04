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

import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * ML-KEM provider using Java 23+ native javax.crypto.KEM API via reflection.
 */
internal class JavaMlKemProvider : MlKemProvider {
    companion object {
        private const val MLKEM768_PUBLIC_KEY_SIZE = 1184

        // X.509 wrapper for ML-KEM-768 public keys
        private val X509_PREFIX = byteArrayOf(
            0x30, 0x82.toByte(), 0x04, 0xb2.toByte(), // SEQUENCE
            0x30, 0x0b, // SEQUENCE
            0x06, 0x09, // OID
            0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
            0x03, 0x82.toByte(), 0x04, 0xa1.toByte(), // BIT STRING
            0x00, // no unused bits
        )
    }

    private val kemInstance: Any

    init {
        try {
            val kemClass = Class.forName("javax.crypto.KEM")
            val getInstance = kemClass.getMethod("getInstance", String::class.java)
            kemInstance = getInstance.invoke(null, "ML-KEM")
        } catch (e: Exception) {
            throw IOException("Failed to initialize Java KEM API", e)
        }
    }

    override fun generateKeyPair(): MlKemKeyPair {
        try {
            val kpg = KeyPairGenerator.getInstance("ML-KEM-768")
            val keyPair = kpg.generateKeyPair()

            val x509PublicKey = keyPair.public.encoded
            val pkcs8PrivateKey = keyPair.private.encoded

            val rawPublicKey = extractRawMlKemPublicKey(x509PublicKey)
            return MlKemKeyPair(rawPublicKey, pkcs8PrivateKey)
        } catch (e: Exception) {
            throw IOException("ML-KEM-768 key generation failed", e)
        }
    }

    override fun encapsulate(publicKey: ByteArray): MlKemEncapsulationResult {
        try {
            val x509Encoded = wrapRawMlKemPublicKey(publicKey)
            val kf = KeyFactory.getInstance("ML-KEM")
            val pubKey = kf.generatePublic(X509EncodedKeySpec(x509Encoded))

            val kemClass = Class.forName("javax.crypto.KEM")
            val newEncapsulator = kemClass.getMethod("newEncapsulator", java.security.PublicKey::class.java)
            val encapsulator = newEncapsulator.invoke(kemInstance, pubKey)

            val encapsulatorClass = Class.forName("javax.crypto.KEM\$Encapsulator")
            val encapsulateMethod = encapsulatorClass.getMethod("encapsulate")
            val encapsulated = encapsulateMethod.invoke(encapsulator)

            val encapsulatedClass = Class.forName("javax.crypto.KEM\$Encapsulated")
            val encapsulationMethod = encapsulatedClass.getMethod("encapsulation")
            val ciphertext = encapsulationMethod.invoke(encapsulated) as ByteArray

            val keyMethod = encapsulatedClass.getMethod("key")
            val secretKey = keyMethod.invoke(encapsulated) as javax.crypto.SecretKey
            val sharedSecret = secretKey.encoded

            return MlKemEncapsulationResult(ciphertext, sharedSecret)
        } catch (e: Exception) {
            throw IOException("ML-KEM encapsulation failed", e)
        }
    }

    override fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
        try {
            val kf = KeyFactory.getInstance("ML-KEM")
            val privKey: PrivateKey = kf.generatePrivate(PKCS8EncodedKeySpec(privateKey))

            val kemClass = Class.forName("javax.crypto.KEM")
            val newDecapsulator = kemClass.getMethod("newDecapsulator", PrivateKey::class.java)
            val decapsulator = newDecapsulator.invoke(kemInstance, privKey)

            val decapsulatorClass = Class.forName("javax.crypto.KEM\$Decapsulator")
            val decapsulateMethod = decapsulatorClass.getMethod("decapsulate", ByteArray::class.java)
            val secretKey = decapsulateMethod.invoke(decapsulator, ciphertext) as javax.crypto.SecretKey

            return secretKey.encoded
        } catch (e: Exception) {
            throw IOException("ML-KEM decapsulation failed", e)
        }
    }

    private fun extractRawMlKemPublicKey(x509Encoded: ByteArray): ByteArray {
        if (x509Encoded.size < 22) throw IOException("X.509 encoded ML-KEM public key too short")
        if (x509Encoded[0] != 0x30.toByte()) throw IOException("Invalid X.509 encoding: expected SEQUENCE tag")
        if (x509Encoded[17] != 0x03.toByte()) throw IOException("Invalid X.509 encoding: BIT STRING not found")
        if (x509Encoded[21] != 0x00.toByte()) throw IOException("Invalid X.509 encoding: unexpected unused bits")

        val rawKey = ByteArray(MLKEM768_PUBLIC_KEY_SIZE)
        System.arraycopy(x509Encoded, 22, rawKey, 0, MLKEM768_PUBLIC_KEY_SIZE)
        return rawKey
    }

    private fun wrapRawMlKemPublicKey(rawKey: ByteArray): ByteArray {
        if (rawKey.size != MLKEM768_PUBLIC_KEY_SIZE) {
            throw IOException("Invalid raw ML-KEM public key size: ${rawKey.size}")
        }
        val x509 = ByteArray(X509_PREFIX.size + MLKEM768_PUBLIC_KEY_SIZE)
        System.arraycopy(X509_PREFIX, 0, x509, 0, X509_PREFIX.size)
        System.arraycopy(rawKey, 0, x509, X509_PREFIX.size, MLKEM768_PUBLIC_KEY_SIZE)
        return x509
    }
}
