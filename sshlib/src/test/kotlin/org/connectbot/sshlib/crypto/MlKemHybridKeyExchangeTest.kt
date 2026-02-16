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
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MlKemHybridKeyExchangeTest {

    private val fakeMlKemPublicKey = ByteArray(1184) { (it % 256).toByte() }
    private val fakeMlKemPrivateKey = ByteArray(2400) { ((it * 3) % 256).toByte() }
    private val fakeMlKemCiphertext = ByteArray(1088) { ((it * 7) % 256).toByte() }
    private val fakeMlKemSharedSecret = ByteArray(32) { ((it + 10) % 256).toByte() }

    private val fakeX25519Private = ByteArray(32) { ((it + 1) % 256).toByte() }
    private val fakeX25519Public = ByteArray(32) { ((it + 50) % 256).toByte() }
    private val fakeX25519ServerPublic = ByteArray(32) { ((it + 100) % 256).toByte() }
    private val fakeX25519SharedSecret = ByteArray(32) { ((it + 200) % 256).toByte() }

    private val mockMlKemProvider = object : MlKemProvider {
        override fun generateKeyPair(): MlKemKeyPair = MlKemKeyPair(fakeMlKemPublicKey.clone(), fakeMlKemPrivateKey.clone())

        override fun encapsulate(publicKey: ByteArray): MlKemEncapsulationResult = MlKemEncapsulationResult(fakeMlKemCiphertext.clone(), fakeMlKemSharedSecret.clone())

        override fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray = fakeMlKemSharedSecret.clone()
    }

    private val mockX25519Provider = object : X25519Provider {
        override fun generatePrivateKey(): ByteArray = fakeX25519Private.clone()
        override fun publicFromPrivate(privateKey: ByteArray): ByteArray = fakeX25519Public.clone()
        override fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray = fakeX25519SharedSecret.clone()
    }

    @Test
    fun `client init message is 1216 bytes`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        val clientInit = kex.generateClientKeys()
        assertEquals(1216, clientInit.size)
    }

    @Test
    fun `client init message format is mlkem_pubkey then x25519_pubkey`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        val clientInit = kex.generateClientKeys()

        val mlKemPart = clientInit.copyOfRange(0, 1184)
        val x25519Part = clientInit.copyOfRange(1184, 1216)

        assertContentEquals(fakeMlKemPublicKey, mlKemPart)
        assertContentEquals(fakeX25519Public, x25519Part)
    }

    @Test
    fun `server reply parsing - valid 1120 byte reply`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        kex.generateClientKeys()

        val serverReply = ByteArray(1120)
        System.arraycopy(fakeMlKemCiphertext, 0, serverReply, 0, 1088)
        System.arraycopy(fakeX25519ServerPublic, 0, serverReply, 1088, 32)

        val sharedSecret = kex.computeSharedSecret(serverReply)
        assert(sharedSecret.isNotEmpty()) { "Shared secret should not be empty" }
        // 4 bytes length prefix + 32 bytes SHA-256 hash
        assertEquals(36, sharedSecret.size)
    }

    @Test
    fun `shared secret is wire-encoded SSH string of SHA-256(mlkem_ss x25519_ss)`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        kex.generateClientKeys()

        val serverReply = ByteArray(1120)
        System.arraycopy(fakeMlKemCiphertext, 0, serverReply, 0, 1088)
        System.arraycopy(fakeX25519ServerPublic, 0, serverReply, 1088, 32)

        val sharedSecret = kex.computeSharedSecret(serverReply)

        val combined = fakeMlKemSharedSecret + fakeX25519SharedSecret
        val expectedK = MessageDigest.getInstance("SHA-256").digest(combined)
        val expectedEncoded = encodeSshString(expectedK)

        assertContentEquals(expectedEncoded, sharedSecret)
    }

    @Test
    fun `rejects server reply with wrong size`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        kex.generateClientKeys()

        assertFailsWith<SshException> {
            kex.computeSharedSecret(ByteArray(100))
        }
    }

    @Test
    fun `rejects all-zero X25519 shared secret`() {
        val zeroX25519Provider = object : X25519Provider {
            override fun generatePrivateKey(): ByteArray = fakeX25519Private.clone()
            override fun publicFromPrivate(privateKey: ByteArray): ByteArray = fakeX25519Public.clone()
            override fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray = ByteArray(32) // all zeros
        }

        val kex = MlKemHybridKeyExchange(mockMlKemProvider, zeroX25519Provider)
        kex.generateClientKeys()

        val serverReply = ByteArray(1120)
        assertFailsWith<SshException> {
            kex.computeSharedSecret(serverReply)
        }
    }

    @Test
    fun `hash algorithm is SHA-256`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        assertEquals("SHA-256", kex.hashAlgorithm)
    }

    @Test
    fun `computeSharedSecret fails before generateClientKeys`() {
        val kex = MlKemHybridKeyExchange(mockMlKemProvider, mockX25519Provider)
        assertFailsWith<SshException> {
            kex.computeSharedSecret(ByteArray(1120))
        }
    }
}
