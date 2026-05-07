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

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class JavaMlKemProviderTest {

    @Test
    fun `constructor reports initialization failure as IOException when Java KEM is unavailable`() {
        val result = runCatching { JavaMlKemProvider() }
        assumeTrue(result.isFailure, "Java ML-KEM is available on this runtime")

        val exception = result.exceptionOrNull()
        assertIs<IOException>(exception)
        assertEquals("Failed to initialize Java KEM API", exception.message)
        assertTrue(exception.cause is Exception)
    }

    @Test
    fun `generateKeyPair returns raw public key and encoded private key`() {
        val provider = nativeProvider()

        val keyPair = provider.generateKeyPair()

        assertEquals(1184, keyPair.publicKey.size)
        assertTrue(keyPair.privateKey.isNotEmpty())
    }

    @Test
    fun `encapsulate and decapsulate agree on shared secret`() {
        val provider = nativeProvider()
        val keyPair = provider.generateKeyPair()

        val encapsulation = provider.encapsulate(keyPair.publicKey)
        val decapsulated = provider.decapsulate(keyPair.privateKey, encapsulation.ciphertext)

        assertEquals(1088, encapsulation.ciphertext.size)
        assertEquals(32, encapsulation.sharedSecret.size)
        assertContentEquals(encapsulation.sharedSecret, decapsulated)
    }

    @Test
    fun `generateKeyPair returns different keys each time`() {
        val provider = nativeProvider()

        val first = provider.generateKeyPair()
        val second = provider.generateKeyPair()

        assertTrue(!first.publicKey.contentEquals(second.publicKey))
        assertTrue(!first.privateKey.contentEquals(second.privateKey))
    }

    @Test
    fun `wrapRawMlKemPublicKey rejects keys with wrong sizes`() {
        assertIOException("Invalid raw ML-KEM public key size: 1183") {
            JavaMlKemProvider.wrapRawMlKemPublicKey(ByteArray(1183))
        }
        assertIOException("Invalid raw ML-KEM public key size: 1185") {
            JavaMlKemProvider.wrapRawMlKemPublicKey(ByteArray(1185))
        }
    }

    @Test
    fun `wrapRawMlKemPublicKey returns x509 encoded ML-KEM key`() {
        val rawKey = ByteArray(1184) { (it % 251).toByte() }

        val x509 = JavaMlKemProvider.wrapRawMlKemPublicKey(rawKey)

        assertEquals(1206, x509.size)
        assertContentEquals(
            byteArrayOf(
                0x30,
                0x82.toByte(),
                0x04,
                0xb2.toByte(),
                0x30,
                0x0b,
                0x06,
                0x09,
                0x60,
                0x86.toByte(),
                0x48,
                0x01,
                0x65,
                0x03,
                0x04,
                0x04,
                0x02,
                0x03,
                0x82.toByte(),
                0x04,
                0xa1.toByte(),
                0x00,
            ),
            x509.copyOfRange(0, 22),
        )
        assertContentEquals(rawKey, x509.copyOfRange(22, x509.size))
    }

    @Test
    fun `extractRawMlKemPublicKey returns raw key bytes from x509 encoding`() {
        val rawKey = ByteArray(1184) { ((it * 3) % 251).toByte() }
        val x509 = JavaMlKemProvider.wrapRawMlKemPublicKey(rawKey)

        val extracted = JavaMlKemProvider.extractRawMlKemPublicKey(x509)

        assertContentEquals(rawKey, extracted)
    }

    @Test
    fun `extractRawMlKemPublicKey rejects malformed x509 envelope`() {
        assertIOException("X.509 encoded ML-KEM public key too short") {
            JavaMlKemProvider.extractRawMlKemPublicKey(ByteArray(21))
        }

        assertIOException("X.509 encoded ML-KEM public key missing raw key bytes") {
            JavaMlKemProvider.extractRawMlKemPublicKey(validX509().copyOf(22 + 1183))
        }

        assertIOException("Invalid X.509 encoding: expected SEQUENCE tag") {
            JavaMlKemProvider.extractRawMlKemPublicKey(validX509().also { it[0] = 0x31 })
        }

        assertIOException("Invalid X.509 encoding: BIT STRING not found") {
            JavaMlKemProvider.extractRawMlKemPublicKey(validX509().also { it[17] = 0x04 })
        }

        assertIOException("Invalid X.509 encoding: unexpected unused bits") {
            JavaMlKemProvider.extractRawMlKemPublicKey(validX509().also { it[21] = 0x01 })
        }
    }

    @Test
    fun `encapsulate wraps invalid raw public key as IOException`() {
        val provider = nativeProvider()

        val exception = assertFailsWith<IOException> {
            provider.encapsulate(ByteArray(100))
        }

        assertEquals("ML-KEM encapsulation failed", exception.message)
        assertIs<IOException>(exception.cause)
        assertEquals("Invalid raw ML-KEM public key size: 100", exception.cause?.message)
    }

    @Test
    fun `decapsulate wraps invalid private key as IOException`() {
        val provider = nativeProvider()

        val exception = assertFailsWith<IOException> {
            provider.decapsulate(ByteArray(100), ByteArray(1088))
        }

        assertEquals("ML-KEM decapsulation failed", exception.message)
        assertTrue(exception.cause is Exception)
    }

    @Test
    fun `native decapsulate wraps invalid ciphertext as IOException`() {
        val provider = nativeProvider()
        val keyPair = provider.generateKeyPair()

        val exception = assertFailsWith<IOException> {
            provider.decapsulate(keyPair.privateKey, ByteArray(100))
        }

        assertEquals("ML-KEM decapsulation failed", exception.message)
        assertTrue(exception.cause is Exception)
    }

    private fun validX509(): ByteArray = JavaMlKemProvider.wrapRawMlKemPublicKey(ByteArray(1184))

    private fun nativeProvider(): JavaMlKemProvider {
        val result = runCatching { JavaMlKemProvider() }
        assumeTrue(result.isSuccess, "Java ML-KEM is unavailable: ${result.exceptionOrNull()?.message}")
        return result.getOrThrow()
    }

    private inline fun assertIOException(expectedMessage: String, block: () -> Unit) {
        val exception = assertFailsWith<IOException> {
            block()
        }
        assertEquals(expectedMessage, exception.message)
    }
}
