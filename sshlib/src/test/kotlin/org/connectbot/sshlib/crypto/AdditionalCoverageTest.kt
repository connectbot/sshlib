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

import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import java.io.IOException
import java.security.PublicKey
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class AdditionalCoverageTest {

    @Test
    fun `JavaMlKemProvider wraps and validates raw ML-KEM public keys`() {
        val rawKey = ByteArray(1184) { (it and 0xff).toByte() }

        val wrapped = JavaMlKemProvider.wrapRawMlKemPublicKey(rawKey)
        assertEquals(1206, wrapped.size)
        assertContentEquals(rawKey, JavaMlKemProvider.extractRawMlKemPublicKey(wrapped))

        assertFailsWith<IOException> {
            JavaMlKemProvider.wrapRawMlKemPublicKey(ByteArray(32))
        }
        assertFailsWith<IOException> {
            JavaMlKemProvider.extractRawMlKemPublicKey(ByteArray(4))
        }
        assertFailsWith<IOException> {
            JavaMlKemProvider.extractRawMlKemPublicKey(wrapped.copyOf().also { it[0] = 0x31 })
        }
        assertFailsWith<IOException> {
            JavaMlKemProvider.extractRawMlKemPublicKey(wrapped.copyOf().also { it[17] = 0x04 })
        }
        assertFailsWith<IOException> {
            JavaMlKemProvider.extractRawMlKemPublicKey(wrapped.copyOf().also { it[21] = 0x01 })
        }
        assertFailsWith<IOException> {
            JavaMlKemProvider.extractRawMlKemPublicKey(wrapped.copyOf(32))
        }
    }

    @Test
    fun `AesCtrCipher rejects invalid key and iv sizes`() {
        assertFailsWith<IllegalArgumentException> {
            AesCtrCipher(ByteArray(15), ByteArray(16), forEncryption = true)
        }
        assertFailsWith<IllegalArgumentException> {
            AesCtrCipher(ByteArray(16), ByteArray(15), forEncryption = true)
        }
    }

    @Test
    fun `inferKeyType rejects unsupported public keys`() {
        val key = object : PublicKey {
            override fun getAlgorithm(): String = "Unsupported"
            override fun getFormat(): String = "X.509"
            override fun getEncoded(): ByteArray = byteArrayOf(1, 2, 3)
        }

        assertFalse(isEd25519Key(key))
        assertFailsWith<SshException> {
            inferKeyType(key)
        }
    }
}
