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

import org.connectbot.sshlib.crypto.ed25519.Ed25519KeyPairGenerator
import org.connectbot.sshlib.crypto.ed25519.Ed25519PublicKey
import org.junit.jupiter.api.Test
import java.security.PublicKey
import kotlin.test.assertEquals

class KeyTypesTest {

    @Test
    fun `inferKeyType recognizes OID algorithm name as Ed25519`() {
        val original = Ed25519KeyPairGenerator().generateKeyPair().public as Ed25519PublicKey
        val wrappedKey = object : PublicKey {
            override fun getAlgorithm() = "1.3.101.112"
            override fun getFormat() = original.format
            override fun getEncoded() = original.encoded
        }
        assertEquals("ssh-ed25519", inferKeyType(wrappedKey))
    }

    @Test
    fun `inferKeyType recognizes EdDSA class name`() {
        val original = Ed25519KeyPairGenerator().generateKeyPair().public as Ed25519PublicKey
        val wrappedKey = OpenSslEdDsaPublicKeyStub(original)
        assertEquals("ssh-ed25519", inferKeyType(wrappedKey))
    }

    private class OpenSslEdDsaPublicKeyStub(private val delegate: PublicKey) : PublicKey {
        override fun getAlgorithm() = "UnknownAlgorithm"
        override fun getFormat() = delegate.format
        override fun getEncoded() = delegate.encoded
    }
}
