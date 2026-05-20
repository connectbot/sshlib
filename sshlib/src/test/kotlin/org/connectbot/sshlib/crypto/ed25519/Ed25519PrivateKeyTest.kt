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

import org.connectbot.sshlib.crypto.DerReader
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Ed25519PrivateKeyTest {
    private val testSeed = ByteArray(32) { it.toByte() }

    @Test
    fun `seed constructor stores seed`() {
        val key = Ed25519PrivateKey(testSeed)
        assertContentEquals(testSeed, key.getSeed())
    }

    @Test
    fun `algorithm is EdDSA`() {
        val key = Ed25519PrivateKey(testSeed)
        assertEquals("EdDSA", key.algorithm)
    }

    @Test
    fun `format is PKCS#8`() {
        val key = Ed25519PrivateKey(testSeed)
        assertEquals("PKCS#8", key.format)
    }

    @Test
    fun `getEncoded produces valid PKCS#8 DER`() {
        val key = Ed25519PrivateKey(testSeed)
        val encoded = key.encoded

        val reader = DerReader(encoded)
        reader.readSequence { seq ->
            val version = seq.readInteger()
            assertEquals(BigInteger.ZERO, version)
            seq.readSequence { algId ->
                val oid = algId.readObjectIdentifier()
                assertContentEquals(byteArrayOf(0x2b, 0x65, 0x70), oid)
            }
            val privateKeyOctetString = seq.readOctetString()
            val innerReader = DerReader(privateKeyOctetString)
            val seed = innerReader.readOctetString()
            assertContentEquals(testSeed, seed)
        }
    }

    @Test
    fun `PKCS#8 roundtrip preserves seed`() {
        val original = Ed25519PrivateKey(testSeed)
        val encoded = original.encoded
        val restored = Ed25519PrivateKey(PKCS8EncodedKeySpec(encoded))
        assertContentEquals(testSeed, restored.getSeed())
    }

    @Test
    fun `PKCS#8 constructor accepts raw 32-byte seed`() {
        val key = Ed25519PrivateKey(PKCS8EncodedKeySpec(testSeed))
        assertContentEquals(testSeed, key.getSeed())
    }

    @Test
    fun `PKCS#8 constructor rejects wrong version`() {
        val key = Ed25519PrivateKey(testSeed)
        val encoded = key.encoded.clone()
        // Version field is at offset: SEQUENCE tag(1) + length(1) + INTEGER tag(1) + length(1) + value
        // Find the version integer value byte and change it
        val reader = DerReader(encoded)
        // Manually patch version: in PKCS#8, the version INTEGER 0 is encoded as 02 01 00
        // Search for the pattern and change 00 to 01
        val versionIndex = encoded.indexOfSequence(byteArrayOf(0x02, 0x01, 0x00))
        encoded[versionIndex + 2] = 0x01
        assertFailsWith<InvalidKeySpecException> {
            Ed25519PrivateKey(PKCS8EncodedKeySpec(encoded))
        }
    }

    @Test
    fun `PKCS#8 constructor rejects wrong OID`() {
        val key = Ed25519PrivateKey(testSeed)
        val encoded = key.encoded.clone()
        // Ed25519 OID is 2b 65 70, change last byte
        val oidIndex = encoded.indexOfSequence(byteArrayOf(0x2b, 0x65, 0x70))
        encoded[oidIndex + 2] = 0x71
        assertFailsWith<InvalidKeySpecException> {
            Ed25519PrivateKey(PKCS8EncodedKeySpec(encoded))
        }
    }

    @Test
    fun `PKCS#8 constructor rejects wrong seed length`() {
        val shortSeed = ByteArray(8) { it.toByte() }
        val encoded = org.connectbot.sshlib.crypto.encodeDer {
            sequence {
                integer(BigInteger.ZERO)
                sequence {
                    objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70))
                }
                octetString(org.connectbot.sshlib.crypto.encodeDer { octetString(shortSeed) })
            }
        }
        assertFailsWith<InvalidKeySpecException> {
            Ed25519PrivateKey(PKCS8EncodedKeySpec(encoded))
        }
    }

    @Test
    fun `PKCS#8 constructor rejects malformed DER`() {
        val garbage = ByteArray(64) { 0xFF.toByte() }
        assertFailsWith<InvalidKeySpecException> {
            Ed25519PrivateKey(PKCS8EncodedKeySpec(garbage))
        }
    }

    @Test
    fun `equal keys have same hashCode`() {
        val key1 = Ed25519PrivateKey(testSeed.clone())
        val key2 = Ed25519PrivateKey(testSeed.clone())
        assertEquals(key1.hashCode(), key2.hashCode())
    }

    @Test
    fun `equal keys are equal`() {
        val key1 = Ed25519PrivateKey(testSeed.clone())
        val key2 = Ed25519PrivateKey(testSeed.clone())
        assertEquals(key1, key2)
    }

    @Test
    fun `different keys are not equal`() {
        val key1 = Ed25519PrivateKey(testSeed)
        val otherSeed = ByteArray(32) { (it + 1).toByte() }
        val key2 = Ed25519PrivateKey(otherSeed)
        assertNotEquals(key1, key2)
    }

    @Test
    fun `not equal to non-Ed25519PrivateKey`() {
        val key = Ed25519PrivateKey(testSeed)
        assertFalse(key.equals("not a key"))
    }

    @Test
    fun `destroy zeros out seed`() {
        val seed = testSeed.clone()
        val key = Ed25519PrivateKey(seed)
        assertFalse(key.isDestroyed)

        key.destroy()

        assertTrue(key.isDestroyed)
        assertContentEquals(ByteArray(32), key.getSeed())
    }

    private fun ByteArray.indexOfSequence(seq: ByteArray): Int {
        outer@ for (i in 0..this.size - seq.size) {
            for (j in seq.indices) {
                if (this[i + j] != seq[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
