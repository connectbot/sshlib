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

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class KeyDerivationTest {

    private val sharedSecret = ByteArray(20) { (it + 1).toByte() }
    private val exchangeHash = ByteArray(20) { (it + 100).toByte() }
    private val sessionId = ByteArray(20) { (it + 50).toByte() }

    @Test
    fun `derived keys have correct lengths`() {
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId)
        val keys = kd.deriveKeys(16, 32, 20)
        assertEquals(16, keys.initialIvClientToServer.size)
        assertEquals(16, keys.initialIvServerToClient.size)
        assertEquals(32, keys.encryptionKeyClientToServer.size)
        assertEquals(32, keys.encryptionKeyServerToClient.size)
        assertEquals(20, keys.integrityKeyClientToServer.size)
        assertEquals(20, keys.integrityKeyServerToClient.size)
    }

    @Test
    fun `client and server keys are different`() {
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId)
        val keys = kd.deriveKeys(16, 16, 20)
        assertFalse(
            keys.initialIvClientToServer.contentEquals(keys.initialIvServerToClient),
            "IVs must differ between directions",
        )
        assertFalse(
            keys.encryptionKeyClientToServer.contentEquals(keys.encryptionKeyServerToClient),
            "Encryption keys must differ between directions",
        )
    }

    @Test
    fun `derivation is deterministic`() {
        val kd1 = KeyDerivation(sharedSecret, exchangeHash, sessionId)
        val kd2 = KeyDerivation(sharedSecret, exchangeHash, sessionId)
        val keys1 = kd1.deriveKeys(16, 16, 20)
        val keys2 = kd2.deriveKeys(16, 16, 20)
        assertContentEquals(keys1.encryptionKeyClientToServer, keys2.encryptionKeyClientToServer)
    }

    @Test
    fun `different session IDs produce different keys`() {
        val kd1 = KeyDerivation(sharedSecret, exchangeHash, ByteArray(20) { 1 })
        val kd2 = KeyDerivation(sharedSecret, exchangeHash, ByteArray(20) { 2 })
        val keys1 = kd1.deriveKeys(16, 16, 20)
        val keys2 = kd2.deriveKeys(16, 16, 20)
        assertFalse(
            keys1.encryptionKeyClientToServer.contentEquals(keys2.encryptionKeyClientToServer),
        )
    }

    @Test
    fun `key longer than hash digest uses extended derivation`() {
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId, "SHA-1")
        // SHA-1 produces 20 bytes; request 40 bytes to force K2 computation
        val key = kd.deriveKeys(40, 40, 40)
        assertEquals(40, key.initialIvClientToServer.size)
        // First 20 bytes come from K1, next 20 from K2 — they should differ
        val first = key.initialIvClientToServer.copyOfRange(0, 20)
        val second = key.initialIvClientToServer.copyOfRange(20, 40)
        assertFalse(first.contentEquals(second), "Extended key must not repeat the initial block")
    }

    @Test
    fun `zeroize clears all key material`() {
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId)
        val keys = kd.deriveKeys(16, 16, 20)
        val snapshot = keys.encryptionKeyClientToServer.copyOf()
        keys.zeroize()
        assertFalse(
            keys.encryptionKeyClientToServer.contentEquals(snapshot),
            "zeroize must clear key bytes",
        )
        assertContentEquals(ByteArray(16), keys.encryptionKeyClientToServer)
    }

    @Test
    fun `zeroize clears all six key arrays`() {
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId)
        val keys = kd.deriveKeys(16, 32, 20)
        keys.zeroize()
        assertContentEquals(ByteArray(16), keys.initialIvClientToServer)
        assertContentEquals(ByteArray(16), keys.initialIvServerToClient)
        assertContentEquals(ByteArray(32), keys.encryptionKeyClientToServer)
        assertContentEquals(ByteArray(32), keys.encryptionKeyServerToClient)
        assertContentEquals(ByteArray(20), keys.integrityKeyClientToServer)
        assertContentEquals(ByteArray(20), keys.integrityKeyServerToClient)
    }

    @Test
    fun `SHA-256 derivation produces keys of requested length`() {
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId, "SHA-256")
        val keys = kd.deriveKeys(16, 32, 32)
        assertEquals(32, keys.encryptionKeyClientToServer.size)
    }

    @Test
    fun `derivation subtraction boundary - exact hash size key has correct length`() {
        // Request key exactly equal to hash output size (20 for SHA-1)
        val kd = KeyDerivation(sharedSecret, exchangeHash, sessionId, "SHA-1")
        val keys = kd.deriveKeys(20, 20, 20)
        assertEquals(20, keys.initialIvClientToServer.size)
        // Verify non-zero output (not all zeros)
        assertNotEquals(ByteArray(20).toList(), keys.initialIvClientToServer.toList())
    }
}
