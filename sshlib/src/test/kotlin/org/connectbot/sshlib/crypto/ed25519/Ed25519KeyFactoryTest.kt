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

package org.connectbot.sshlib.crypto.ed25519

import org.junit.jupiter.api.Test
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame

class Ed25519KeyFactoryTest {
    private val provider = Ed25519Provider()
    private val factory = KeyFactory.getInstance(Ed25519Provider.KEY_ALGORITHM, provider)
    private val testSeed = ByteArray(32) { it.toByte() }

    private fun generateKeyPair(): java.security.KeyPair = Ed25519KeyPairGenerator().generateKeyPair()

    @Test
    fun `generatePublic with X509EncodedKeySpec`() {
        val original = generateKeyPair().public as Ed25519PublicKey
        val spec = X509EncodedKeySpec(original.encoded)
        val restored = factory.generatePublic(spec)
        assertIs<Ed25519PublicKey>(restored)
        assertEquals(original, restored)
    }

    @Test
    fun `generatePublic rejects non-X509EncodedKeySpec`() {
        val spec = PKCS8EncodedKeySpec(ByteArray(32))
        assertFailsWith<InvalidKeySpecException> {
            factory.generatePublic(spec)
        }
    }

    @Test
    fun `generatePrivate with PKCS8EncodedKeySpec`() {
        val original = Ed25519PrivateKey(testSeed)
        val spec = PKCS8EncodedKeySpec(original.encoded)
        val restored = factory.generatePrivate(spec)
        val restoredKey = assertIs<Ed25519PrivateKey>(restored)
        assertContentEquals(testSeed, restoredKey.getSeed())
    }

    @Test
    fun `generatePrivate rejects non-PKCS8EncodedKeySpec`() {
        val spec = X509EncodedKeySpec(ByteArray(32))
        assertFailsWith<InvalidKeySpecException> {
            factory.generatePrivate(spec)
        }
    }

    @Test
    fun `getKeySpec throws`() {
        val key = Ed25519PrivateKey(testSeed)
        assertFailsWith<InvalidKeySpecException> {
            factory.getKeySpec(key, KeySpec::class.java)
        }
    }

    @Test
    fun `translateKey returns same Ed25519PublicKey`() {
        val key = generateKeyPair().public as Ed25519PublicKey
        val result = factory.translateKey(key)
        assertSame(key, result)
    }

    @Test
    fun `translateKey returns same Ed25519PrivateKey`() {
        val key = Ed25519PrivateKey(testSeed)
        val result = factory.translateKey(key)
        assertSame(key, result)
    }

    @Test
    fun `translateKey converts foreign X509 public key`() {
        val original = generateKeyPair().public as Ed25519PublicKey
        val foreignKey = object : PublicKey {
            override fun getAlgorithm() = "EdDSA"
            override fun getFormat() = "X.509"
            override fun getEncoded() = original.encoded
        }
        val result = factory.translateKey(foreignKey)
        assertIs<Ed25519PublicKey>(result)
        assertEquals(original, result)
    }

    @Test
    fun `translateKey converts foreign PKCS#8 private key`() {
        val original = Ed25519PrivateKey(testSeed)
        val foreignKey = object : PrivateKey {
            override fun getAlgorithm() = "EdDSA"
            override fun getFormat() = "PKCS#8"
            override fun getEncoded() = original.encoded
        }
        val resultKey = assertIs<Ed25519PrivateKey>(factory.translateKey(foreignKey))
        assertContentEquals(testSeed, resultKey.getSeed())
    }

    @Test
    fun `translateKey converts public key with non-standard format`() {
        val original = generateKeyPair().public as Ed25519PublicKey
        val foreignKey = object : PublicKey {
            override fun getAlgorithm() = "1.3.101.112"
            override fun getFormat() = "RAW"
            override fun getEncoded() = original.encoded
        }
        val result = factory.translateKey(foreignKey)
        assertIs<Ed25519PublicKey>(result)
        assertEquals(original, result)
    }

    @Test
    fun `translateKey converts private key with non-standard format`() {
        val original = Ed25519PrivateKey(testSeed)
        val foreignKey = object : PrivateKey {
            override fun getAlgorithm() = "1.3.101.112"
            override fun getFormat() = "RAW"
            override fun getEncoded() = original.encoded
        }
        val resultKey = assertIs<Ed25519PrivateKey>(factory.translateKey(foreignKey))
        assertContentEquals(testSeed, resultKey.getSeed())
    }

    @Test
    fun `translateKey rejects public key with null encoded`() {
        val foreignKey = object : PublicKey {
            override fun getAlgorithm() = "EdDSA"
            override fun getFormat() = "RAW"
            override fun getEncoded(): ByteArray? = null
        }
        assertFailsWith<InvalidKeyException> {
            factory.translateKey(foreignKey)
        }
    }

    @Test
    fun `translateKey rejects private key with null encoded`() {
        val foreignKey = object : PrivateKey {
            override fun getAlgorithm() = "EdDSA"
            override fun getFormat() = "RAW"
            override fun getEncoded(): ByteArray? = null
        }
        assertFailsWith<InvalidKeyException> {
            factory.translateKey(foreignKey)
        }
    }

    @Test
    fun `translateKey rejects unknown key type`() {
        val foreignKey = object : Key {
            override fun getAlgorithm() = "Unknown"
            override fun getFormat() = "Unknown"
            override fun getEncoded() = ByteArray(32)
        }
        assertFailsWith<InvalidKeyException> {
            factory.translateKey(foreignKey)
        }
    }

    @Test
    fun `translateKey wraps InvalidKeySpecException from bad X509 public key`() {
        val foreignKey = object : PublicKey {
            override fun getAlgorithm() = "EdDSA"
            override fun getFormat() = "X.509"
            override fun getEncoded() = ByteArray(64) { 0xFF.toByte() }
        }
        assertFailsWith<InvalidKeyException> {
            factory.translateKey(foreignKey)
        }
    }

    @Test
    fun `translateKey wraps InvalidKeySpecException from bad PKCS#8 private key`() {
        val foreignKey = object : PrivateKey {
            override fun getAlgorithm() = "EdDSA"
            override fun getFormat() = "PKCS#8"
            override fun getEncoded() = ByteArray(64) { 0xFF.toByte() }
        }
        assertFailsWith<InvalidKeyException> {
            factory.translateKey(foreignKey)
        }
    }
}
