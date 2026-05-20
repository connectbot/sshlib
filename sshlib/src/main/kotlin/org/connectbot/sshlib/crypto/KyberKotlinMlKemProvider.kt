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

import asia.hombre.kyber.KyberCipherText
import asia.hombre.kyber.KyberDecapsulationKey
import asia.hombre.kyber.KyberEncapsulationKey
import asia.hombre.kyber.KyberKeyGenerator
import asia.hombre.kyber.KyberParameter
import asia.hombre.kyber.interfaces.RandomProvider
import java.io.IOException
import java.security.SecureRandom

internal class KyberKotlinMlKemProvider : MlKemProvider {
    private val randomProvider = object : RandomProvider {
        private val secureRandom = SecureRandom()
        override fun fillWithRandom(byteArray: ByteArray) {
            secureRandom.nextBytes(byteArray)
        }
    }

    override fun generateKeyPair(): MlKemKeyPair {
        try {
            val keyPair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768, randomProvider)
            return MlKemKeyPair(
                publicKey = keyPair.encapsulationKey.fullBytes,
                privateKey = keyPair.decapsulationKey.fullBytes,
            )
        } catch (e: Exception) {
            throw IOException("Failed to generate Kyber key pair", e)
        }
    }

    override fun encapsulate(publicKey: ByteArray): MlKemEncapsulationResult {
        try {
            val encapsKey = KyberEncapsulationKey.fromBytes(publicKey)
            val result = encapsKey.encapsulate(randomProvider)
            return MlKemEncapsulationResult(
                ciphertext = result.cipherText.fullBytes,
                sharedSecret = result.sharedSecretKey,
            )
        } catch (e: Exception) {
            throw IOException("Kyber encapsulation failed", e)
        }
    }

    override fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
        try {
            val decapsKey = KyberDecapsulationKey.fromBytes(privateKey)
            val ct = KyberCipherText.fromBytes(ciphertext)
            return decapsKey.decapsulate(ct)
        } catch (e: Exception) {
            throw IOException("Kyber decapsulation failed", e)
        }
    }
}
