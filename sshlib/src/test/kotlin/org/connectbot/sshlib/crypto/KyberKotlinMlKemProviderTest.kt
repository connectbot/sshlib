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
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

class KyberKotlinMlKemProviderTest {
    private val provider = KyberKotlinMlKemProvider()

    @Test
    fun `generateKeyPair returns valid sizes`() {
        val keyPair = provider.generateKeyPair()
        assertEquals(1184, keyPair.publicKey.size)
        assertEquals(2400, keyPair.privateKey.size)
    }

    @Test
    fun `encapsulate and decapsulate work together`() {
        val keyPair = provider.generateKeyPair()

        val encapsulation = provider.encapsulate(keyPair.publicKey)
        assertNotNull(encapsulation.ciphertext)
        assertEquals(1088, encapsulation.ciphertext.size)
        assertEquals(32, encapsulation.sharedSecret.size)

        val sharedSecret = provider.decapsulate(keyPair.privateKey, encapsulation.ciphertext)
        assertContentEquals(encapsulation.sharedSecret, sharedSecret)
    }

    @Test
    fun `generateKeyPair returns different keys each time`() {
        val kp1 = provider.generateKeyPair()
        val kp2 = provider.generateKeyPair()

        assertNotEquals(kp1.publicKey.toHex(), kp2.publicKey.toHex())
        assertNotEquals(kp1.privateKey.toHex(), kp2.privateKey.toHex())
    }

    @Test
    fun `encapsulate fails with invalid public key size`() {
        assertFailsWith<IOException> {
            provider.encapsulate(ByteArray(100))
        }
    }

    @Test
    fun `decapsulate fails with invalid private key size`() {
        assertFailsWith<IOException> {
            provider.decapsulate(ByteArray(100), ByteArray(1088))
        }
    }

    @Test
    fun `decapsulate fails with invalid ciphertext size`() {
        val keyPair = provider.generateKeyPair()
        assertFailsWith<IOException> {
            provider.decapsulate(keyPair.privateKey, ByteArray(100))
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
