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

package org.connectbot.sshlib.crypto.ed25519

import org.junit.jupiter.api.Test
import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class Ed25519KeyPairGeneratorTest {
    private val generator = Ed25519KeyPairGenerator()

    @Test
    fun `generateKeyPair returns non-null key pair`() {
        val keyPair = generator.generateKeyPair()
        assertNotNull(keyPair)
        assertNotNull(keyPair.public)
        assertNotNull(keyPair.private)
    }

    @Test
    fun `public key is Ed25519PublicKey`() {
        val keyPair = generator.generateKeyPair()
        assertIs<Ed25519PublicKey>(keyPair.public)
    }

    @Test
    fun `private key is Ed25519PrivateKey`() {
        val keyPair = generator.generateKeyPair()
        assertIs<Ed25519PrivateKey>(keyPair.private)
    }

    @Test
    fun `public key has 32 bytes`() {
        val keyPair = generator.generateKeyPair()
        val pubKey = keyPair.public as Ed25519PublicKey
        assertEquals(32, pubKey.getAbyte().size)
    }

    @Test
    fun `private key seed has 32 bytes`() {
        val keyPair = generator.generateKeyPair()
        val privKey = keyPair.private as Ed25519PrivateKey
        assertEquals(32, privKey.getSeed().size)
    }

    @Test
    fun `generated key pairs are unique`() {
        val keyPair1 = generator.generateKeyPair()
        val keyPair2 = generator.generateKeyPair()
        val pub1 = (keyPair1.public as Ed25519PublicKey).getAbyte()
        val pub2 = (keyPair2.public as Ed25519PublicKey).getAbyte()
        assert(!pub1.contentEquals(pub2)) { "Two generated key pairs should differ" }
    }

    @Test
    fun `initialize does not throw`() {
        generator.initialize(256, SecureRandom())
    }
}
