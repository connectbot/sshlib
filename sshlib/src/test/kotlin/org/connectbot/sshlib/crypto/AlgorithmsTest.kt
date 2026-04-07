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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AlgorithmsTest {

    // CipherEntry lookup

    @Test
    fun `CipherEntry fromSshName returns correct entry`() {
        assertEquals(CipherEntry.AES128_CTR, CipherEntry.fromSshName("aes128-ctr"))
        assertEquals(CipherEntry.AES256_CTR, CipherEntry.fromSshName("aes256-ctr"))
        assertEquals(CipherEntry.AES128_CBC, CipherEntry.fromSshName("aes128-cbc"))
        assertEquals(CipherEntry.AES256_CBC, CipherEntry.fromSshName("aes256-cbc"))
        assertEquals(CipherEntry.AES128_GCM, CipherEntry.fromSshName("aes128-gcm@openssh.com"))
        assertEquals(CipherEntry.AES256_GCM, CipherEntry.fromSshName("aes256-gcm@openssh.com"))
        assertEquals(CipherEntry.TRIPLE_DES_CBC, CipherEntry.fromSshName("3des-cbc"))
    }

    @Test
    fun `CipherEntry fromSshName returns null for unknown`() {
        assertNull(CipherEntry.fromSshName("unknown-cipher"))
    }

    @Test
    fun `CipherEntry key lengths are correct`() {
        assertEquals(16, CipherEntry.AES128_CTR.keyLength)
        assertEquals(32, CipherEntry.AES256_CTR.keyLength)
        assertEquals(16, CipherEntry.AES128_CBC.keyLength)
        assertEquals(32, CipherEntry.AES256_CBC.keyLength)
        assertEquals(16, CipherEntry.AES128_GCM.keyLength)
        assertEquals(32, CipherEntry.AES256_GCM.keyLength)
        assertEquals(24, CipherEntry.TRIPLE_DES_CBC.keyLength)
    }

    @Test
    fun `CipherEntry IV lengths are correct`() {
        assertEquals(16, CipherEntry.AES128_CTR.ivLength)
        assertEquals(16, CipherEntry.AES256_CTR.ivLength)
        assertEquals(16, CipherEntry.AES128_CBC.ivLength)
        assertEquals(16, CipherEntry.AES256_CBC.ivLength)
        assertEquals(12, CipherEntry.AES128_GCM.ivLength)
        assertEquals(12, CipherEntry.AES256_GCM.ivLength)
        assertEquals(8, CipherEntry.TRIPLE_DES_CBC.ivLength)
    }

    @Test
    fun `CipherEntry block sizes are correct`() {
        assertEquals(16, CipherEntry.AES128_CTR.blockSize)
        assertEquals(16, CipherEntry.AES256_CTR.blockSize)
        assertEquals(16, CipherEntry.AES128_CBC.blockSize)
        assertEquals(16, CipherEntry.AES256_CBC.blockSize)
        assertEquals(16, CipherEntry.AES128_GCM.blockSize)
        assertEquals(16, CipherEntry.AES256_GCM.blockSize)
        assertEquals(8, CipherEntry.TRIPLE_DES_CBC.blockSize)
    }

    @Test
    fun `CipherEntry isAead flags are correct`() {
        assertTrue(CipherEntry.AES128_GCM.isAead)
        assertTrue(CipherEntry.AES256_GCM.isAead)
        assertFalse(CipherEntry.AES128_CTR.isAead)
        assertFalse(CipherEntry.AES256_CTR.isAead)
        assertFalse(CipherEntry.AES128_CBC.isAead)
        assertFalse(CipherEntry.AES256_CBC.isAead)
        assertFalse(CipherEntry.TRIPLE_DES_CBC.isAead)
    }

    @Test
    fun `CipherEntry create returns Aead for GCM ciphers`() {
        val key = ByteArray(16)
        val iv = ByteArray(12)
        val result = CipherEntry.AES128_GCM.create(key, iv, true)
        assertTrue(result is EncryptionInstance.Aead)
    }

    @Test
    fun `CipherEntry create returns Cipher for CTR ciphers`() {
        val key = ByteArray(16)
        val iv = ByteArray(16)
        val result = CipherEntry.AES128_CTR.create(key, iv, true)
        assertTrue(result is EncryptionInstance.Cipher)
    }

    @Test
    fun `CipherEntry create returns Cipher for CBC ciphers`() {
        val key = ByteArray(16)
        val iv = ByteArray(16)
        val result = CipherEntry.AES128_CBC.create(key, iv, true)
        assertTrue(result is EncryptionInstance.Cipher)
    }

    @Test
    fun `CipherEntry create returns Cipher for 3DES`() {
        val key = ByteArray(24)
        val iv = ByteArray(8)
        val result = CipherEntry.TRIPLE_DES_CBC.create(key, iv, true)
        assertTrue(result is EncryptionInstance.Cipher)
    }

    @Test
    fun `CipherEntry defaults contain all entries`() {
        for (entry in CipherEntry.entries) {
            assertTrue(
                CipherEntry.defaultString.contains(entry.sshName),
                "${entry.sshName} not found in defaultString",
            )
        }
    }

    // MacEntry lookup

    @Test
    fun `MacEntry fromSshName returns correct entry`() {
        assertEquals(MacEntry.HMAC_SHA2_256, MacEntry.fromSshName("hmac-sha2-256"))
        assertEquals(MacEntry.HMAC_SHA2_512, MacEntry.fromSshName("hmac-sha2-512"))
        assertEquals(MacEntry.HMAC_SHA2_256_ETM, MacEntry.fromSshName("hmac-sha2-256-etm@openssh.com"))
        assertEquals(MacEntry.HMAC_SHA2_512_ETM, MacEntry.fromSshName("hmac-sha2-512-etm@openssh.com"))
        assertEquals(MacEntry.HMAC_SHA1, MacEntry.fromSshName("hmac-sha1"))
        assertEquals(MacEntry.HMAC_SHA1_ETM, MacEntry.fromSshName("hmac-sha1-etm@openssh.com"))
    }

    @Test
    fun `MacEntry fromSshName returns null for unknown`() {
        assertNull(MacEntry.fromSshName("unknown-mac"))
    }

    @Test
    fun `MacEntry key lengths are correct`() {
        assertEquals(32, MacEntry.HMAC_SHA2_256.keyLength)
        assertEquals(32, MacEntry.HMAC_SHA2_256_ETM.keyLength)
        assertEquals(64, MacEntry.HMAC_SHA2_512.keyLength)
        assertEquals(64, MacEntry.HMAC_SHA2_512_ETM.keyLength)
        assertEquals(20, MacEntry.HMAC_SHA1.keyLength)
        assertEquals(20, MacEntry.HMAC_SHA1_ETM.keyLength)
    }

    @Test
    fun `MacEntry mac lengths are correct`() {
        assertEquals(32, MacEntry.HMAC_SHA2_256.macLength)
        assertEquals(32, MacEntry.HMAC_SHA2_256_ETM.macLength)
        assertEquals(64, MacEntry.HMAC_SHA2_512.macLength)
        assertEquals(64, MacEntry.HMAC_SHA2_512_ETM.macLength)
        assertEquals(20, MacEntry.HMAC_SHA1.macLength)
        assertEquals(20, MacEntry.HMAC_SHA1_ETM.macLength)
    }

    @Test
    fun `MacEntry isEtm flags are correct`() {
        assertTrue(MacEntry.HMAC_SHA2_256_ETM.isEtm)
        assertTrue(MacEntry.HMAC_SHA2_512_ETM.isEtm)
        assertTrue(MacEntry.HMAC_SHA1_ETM.isEtm)
        assertFalse(MacEntry.HMAC_SHA2_256.isEtm)
        assertFalse(MacEntry.HMAC_SHA2_512.isEtm)
        assertFalse(MacEntry.HMAC_SHA1.isEtm)
    }

    @Test
    fun `MacEntry create returns PacketMac`() {
        val key = ByteArray(32)
        val mac = MacEntry.HMAC_SHA2_256.create(key)
        assertNotNull(mac)
        assertEquals(32, mac.macLength)
    }

    @Test
    fun `MacEntry defaults contain all entries`() {
        for (entry in MacEntry.entries) {
            assertTrue(
                MacEntry.defaultString.contains(entry.sshName),
                "${entry.sshName} not found in defaultString",
            )
        }
    }

    // KexEntry lookup

    @Test
    fun `KexEntry fromSshName returns correct entry`() {
        assertEquals(KexEntry.ECDH_SHA2_NISTP256, KexEntry.fromSshName("ecdh-sha2-nistp256"))
        assertEquals(KexEntry.ECDH_SHA2_NISTP384, KexEntry.fromSshName("ecdh-sha2-nistp384"))
        assertEquals(KexEntry.ECDH_SHA2_NISTP521, KexEntry.fromSshName("ecdh-sha2-nistp521"))
        assertEquals(KexEntry.DH_GROUP18_SHA512, KexEntry.fromSshName("diffie-hellman-group18-sha512"))
        assertEquals(KexEntry.DH_GROUP16_SHA512, KexEntry.fromSshName("diffie-hellman-group16-sha512"))
        assertEquals(KexEntry.DH_GROUP_EXCHANGE_SHA256, KexEntry.fromSshName("diffie-hellman-group-exchange-sha256"))
        assertEquals(KexEntry.DH_GROUP14_SHA256, KexEntry.fromSshName("diffie-hellman-group14-sha256"))
        assertEquals(KexEntry.DH_GROUP14_SHA1, KexEntry.fromSshName("diffie-hellman-group14-sha1"))
        assertEquals(KexEntry.DH_GROUP_EXCHANGE_SHA1, KexEntry.fromSshName("diffie-hellman-group-exchange-sha1"))
        assertEquals(KexEntry.DH_GROUP1_SHA1, KexEntry.fromSshName("diffie-hellman-group1-sha1"))
    }

    @Test
    fun `KexEntry fromSshName returns null for unknown`() {
        assertNull(KexEntry.fromSshName("unknown-kex"))
    }

    @Test
    fun `KexEntry fromSshName returns null for strict kex marker`() {
        assertNull(KexEntry.fromSshName("kex-strict-c-v00@openssh.com"))
    }

    @Test
    fun `KexEntry types are correct`() {
        assertEquals(KexType.ECDH, KexEntry.ECDH_SHA2_NISTP256.type)
        assertEquals(KexType.ECDH, KexEntry.ECDH_SHA2_NISTP384.type)
        assertEquals(KexType.ECDH, KexEntry.ECDH_SHA2_NISTP521.type)
        assertEquals(KexType.DH, KexEntry.DH_GROUP18_SHA512.type)
        assertEquals(KexType.DH, KexEntry.DH_GROUP16_SHA512.type)
        assertEquals(KexType.DH_GEX, KexEntry.DH_GROUP_EXCHANGE_SHA256.type)
        assertEquals(KexType.DH, KexEntry.DH_GROUP14_SHA256.type)
        assertEquals(KexType.DH, KexEntry.DH_GROUP14_SHA1.type)
        assertEquals(KexType.DH_GEX, KexEntry.DH_GROUP_EXCHANGE_SHA1.type)
        assertEquals(KexType.DH, KexEntry.DH_GROUP1_SHA1.type)
    }

    @Test
    fun `KexEntry hash algorithms are correct`() {
        assertEquals("SHA-256", KexEntry.ECDH_SHA2_NISTP256.hashAlgorithm)
        assertEquals("SHA-384", KexEntry.ECDH_SHA2_NISTP384.hashAlgorithm)
        assertEquals("SHA-512", KexEntry.ECDH_SHA2_NISTP521.hashAlgorithm)
        assertEquals("SHA-512", KexEntry.DH_GROUP18_SHA512.hashAlgorithm)
        assertEquals("SHA-512", KexEntry.DH_GROUP16_SHA512.hashAlgorithm)
        assertEquals("SHA-256", KexEntry.DH_GROUP_EXCHANGE_SHA256.hashAlgorithm)
        assertEquals("SHA-256", KexEntry.DH_GROUP14_SHA256.hashAlgorithm)
        assertEquals("SHA-1", KexEntry.DH_GROUP14_SHA1.hashAlgorithm)
        assertEquals("SHA-1", KexEntry.DH_GROUP_EXCHANGE_SHA1.hashAlgorithm)
        assertEquals("SHA-1", KexEntry.DH_GROUP1_SHA1.hashAlgorithm)
    }

    @Test
    fun `KexEntry create returns KexAlgorithm`() {
        val kex = KexEntry.ECDH_SHA2_NISTP256.create()
        assertNotNull(kex)
        assertEquals("SHA-256", kex.hashAlgorithm)
    }

    @Test
    fun `KexEntry defaults exclude DH_GROUP1_SHA1`() {
        assertFalse(KexEntry.defaults.contains(KexEntry.DH_GROUP1_SHA1))
        assertFalse(KexEntry.defaultString.contains("diffie-hellman-group1-sha1"))
    }

    @Test
    fun `KexEntry defaultString contains all default entries`() {
        for (entry in KexEntry.defaults) {
            assertTrue(
                KexEntry.defaultString.contains(entry.sshName),
                "${entry.sshName} not found in defaultString",
            )
        }
    }

    @Test
    fun `KexEntry defaultString includes strict kex marker`() {
        assertTrue(KexEntry.defaultString.contains("kex-strict-c-v00@openssh.com"))
    }

    @Test
    fun `KexEntry MLKEM768X25519 is post-quantum`() {
        assertTrue(KexEntry.MLKEM768X25519_SHA256.isPostQuantum)
    }

    @Test
    fun `KexEntry non-PQ algorithms are not post-quantum`() {
        assertFalse(KexEntry.CURVE25519_SHA256.isPostQuantum)
        assertFalse(KexEntry.ECDH_SHA2_NISTP256.isPostQuantum)
        assertFalse(KexEntry.ECDH_SHA2_NISTP384.isPostQuantum)
        assertFalse(KexEntry.ECDH_SHA2_NISTP521.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP18_SHA512.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP16_SHA512.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP_EXCHANGE_SHA256.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP14_SHA256.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP14_SHA1.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP_EXCHANGE_SHA1.isPostQuantum)
        assertFalse(KexEntry.DH_GROUP1_SHA1.isPostQuantum)
    }

    // SignatureEntry lookup

    @Test
    fun `SignatureEntry fromSshName returns correct entry`() {
        assertEquals(SignatureEntry.SSH_RSA, SignatureEntry.fromSshName("ssh-rsa"))
        assertEquals(SignatureEntry.RSA_SHA2_256, SignatureEntry.fromSshName("rsa-sha2-256"))
        assertEquals(SignatureEntry.RSA_SHA2_512, SignatureEntry.fromSshName("rsa-sha2-512"))
        assertEquals(SignatureEntry.ECDSA_SHA2_NISTP256, SignatureEntry.fromSshName("ecdsa-sha2-nistp256"))
        assertEquals(SignatureEntry.ECDSA_SHA2_NISTP384, SignatureEntry.fromSshName("ecdsa-sha2-nistp384"))
        assertEquals(SignatureEntry.ECDSA_SHA2_NISTP521, SignatureEntry.fromSshName("ecdsa-sha2-nistp521"))
        assertEquals(SignatureEntry.SSH_ED25519, SignatureEntry.fromSshName("ssh-ed25519"))
        assertEquals(SignatureEntry.SSH_ED448, SignatureEntry.fromSshName("ssh-ed448"))
    }

    @Test
    fun `SignatureEntry fromSshName returns null for unknown`() {
        assertNull(SignatureEntry.fromSshName("unknown-sig"))
    }

    @Test
    fun `SignatureEntry RSA variants share same algorithm`() {
        assertSame(SignatureEntry.SSH_RSA.algorithm, SignatureEntry.RSA_SHA2_256.algorithm)
        assertSame(SignatureEntry.SSH_RSA.algorithm, SignatureEntry.RSA_SHA2_512.algorithm)
    }

    @Test
    fun `SignatureEntry defaults contain all entries`() {
        for (entry in SignatureEntry.entries) {
            assertTrue(
                SignatureEntry.defaultString.contains(entry.sshName),
                "${entry.sshName} not found in defaultString",
            )
        }
    }
}
