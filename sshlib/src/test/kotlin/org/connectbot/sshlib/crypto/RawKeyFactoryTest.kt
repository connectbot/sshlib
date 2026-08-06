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

import org.connectbot.sshlib.crypto.ed25519.Ed25519Provider
import org.junit.jupiter.api.Test
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactorySpi
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RawKeyFactoryTest {
    private val rejectingProvider = RejectingRawKeyProvider()

    @Test
    fun `skips provider that advertises algorithm but rejects raw keys`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val providers = listOf(rejectingProvider) + Security.getProviders()

        val restored = RawKeyFactory.generateKeyPair(
            "RSA",
            X509EncodedKeySpec(keyPair.public.encoded),
            PKCS8EncodedKeySpec(keyPair.private.encoded),
            providers,
        )

        assertContentEquals(keyPair.public.encoded, restored.public.encoded)
        assertContentEquals(keyPair.private.encoded, restored.private.encoded)
    }

    @Test
    fun `uses bundled Ed25519 provider without registering it`() {
        val providerNamesBefore = Security.getProviders().map { it.name }
        val seed = ByteArray(32) { it.toByte() }
        val privateSpec = PKCS8EncodedKeySpec(
            encodeDer {
                sequence {
                    integer(java.math.BigInteger.ZERO)
                    sequence { objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70)) }
                    octetString(encodeDer { octetString(seed) })
                }
            },
        )
        val publicSpec = X509EncodedKeySpec(
            encodeDer {
                sequence {
                    sequence { objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70)) }
                    bitString(com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPairFromSeed(seed).publicKey)
                }
            },
        )

        val restored = RawKeyFactory.generateKeyPair(
            "Ed25519",
            publicSpec,
            privateSpec,
            listOf(rejectingProvider, Ed25519Provider()),
        )

        assertEquals("EdDSA", restored.public.algorithm)
        assertEquals("EdDSA", restored.private.algorithm)
        assertEquals(providerNamesBefore, Security.getProviders().map { it.name })
    }

    @Test
    fun `fails when no provider accepts key material`() {
        assertFailsWith<InvalidKeySpecException> {
            RawKeyFactory.generatePublic(
                "Ed25519",
                X509EncodedKeySpec(ByteArray(32)),
                listOf(rejectingProvider),
            )
        }
    }
}

class RejectingRawKeyProvider : Provider("RejectingRawKeyProvider", 1.0, "Rejects raw key material") {
    init {
        for (algorithm in listOf("RSA", "EC", "Ed25519", "Ed448", "X25519")) {
            put("KeyFactory.$algorithm", RejectingRawKeyFactory::class.java.name)
        }
    }
}

class RejectingRawKeyFactory : KeyFactorySpi() {
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey = throw InvalidKeySpecException("Raw keys rejected")

    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey = throw InvalidKeySpecException("Raw keys rejected")

    override fun <T : KeySpec> engineGetKeySpec(key: Key, keySpec: Class<T>): T = throw InvalidKeySpecException("Raw keys rejected")

    override fun engineTranslateKey(key: Key): Key = throw InvalidKeyException("Raw keys rejected")
}
