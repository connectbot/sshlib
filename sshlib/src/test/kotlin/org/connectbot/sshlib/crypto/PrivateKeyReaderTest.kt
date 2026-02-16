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
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PrivateKeyReaderTest {

    private fun readKey(resourcePath: String): String = javaClass.getResourceAsStream("/keys/$resourcePath")!!
        .bufferedReader().readText()

    // OpenSSH format - Ed25519

    @Test
    fun `reads unencrypted OpenSSH Ed25519 key`() {
        val key = PrivateKeyReader.read(readKey("ed25519_unencrypted"))
        assertEquals("ssh-ed25519", key.keyType)
        assertEquals("ssh-ed25519", key.signatureAlgorithm)
        assertNotNull(key.jcaKeyPair.private)
        assertNotNull(key.jcaKeyPair.public)
    }

    @Test
    fun `reads encrypted OpenSSH Ed25519 key`() {
        val key = PrivateKeyReader.read(readKey("ed25519_encrypted"), "testpass")
        assertEquals("ssh-ed25519", key.keyType)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `rejects encrypted Ed25519 key without passphrase`() {
        assertFailsWith<SshException> {
            PrivateKeyReader.read(readKey("ed25519_encrypted"))
        }
    }

    // OpenSSH format - ECDSA

    @Test
    fun `reads unencrypted OpenSSH ECDSA-256 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa256_unencrypted"))
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
        assertEquals("ecdsa-sha2-nistp256", key.signatureAlgorithm)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `reads encrypted OpenSSH ECDSA-256 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa256_encrypted"), "testpass")
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `reads unencrypted OpenSSH ECDSA-384 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa384_unencrypted"))
        assertEquals("ecdsa-sha2-nistp384", key.keyType)
    }

    @Test
    fun `reads unencrypted OpenSSH ECDSA-521 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa521_unencrypted"))
        assertEquals("ecdsa-sha2-nistp521", key.keyType)
    }

    // OpenSSH format - RSA

    @Test
    fun `reads unencrypted OpenSSH RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_unencrypted"))
        assertEquals("ssh-rsa", key.keyType)
        assertEquals("rsa-sha2-512", key.signatureAlgorithm)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `reads encrypted OpenSSH RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_encrypted"), "testpass")
        assertEquals("ssh-rsa", key.keyType)
        assertNotNull(key.jcaKeyPair.private)
    }

    // Traditional PEM format

    @Test
    fun `reads unencrypted PEM RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_pem_unencrypted.pem"))
        assertEquals("ssh-rsa", key.keyType)
        assertEquals("rsa-sha2-512", key.signatureAlgorithm)
    }

    @Test
    fun `reads encrypted PEM RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_pem_encrypted.pem"), "testpass")
        assertEquals("ssh-rsa", key.keyType)
    }

    @Test
    fun `reads unencrypted PEM EC key`() {
        val key = PrivateKeyReader.read(readKey("ec_pem_unencrypted.pem"))
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
    }

    @Test
    fun `reads encrypted PEM EC key`() {
        val key = PrivateKeyReader.read(readKey("ec_pem_encrypted.pem"), "testpass")
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
    }

    // PKCS#8 format

    @Test
    fun `reads PKCS8 Ed25519 key`() {
        val key = PrivateKeyReader.read(readKey("ed25519_pkcs8.pem"))
        assertEquals("ssh-ed25519", key.keyType)
        assertEquals("ssh-ed25519", key.signatureAlgorithm)
    }

    @Test
    fun `reads PKCS8 EC key`() {
        val key = PrivateKeyReader.read(readKey("ec_pkcs8.pem"))
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
    }

    @Test
    fun `reads PKCS8 RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_pkcs8.pem"))
        assertEquals("ssh-rsa", key.keyType)
    }

    // isEncrypted detection

    @Test
    fun `detects unencrypted OpenSSH key`() {
        assertFalse(PrivateKeyReader.isEncrypted(readKey("ed25519_unencrypted")))
    }

    @Test
    fun `detects encrypted OpenSSH key`() {
        assertTrue(PrivateKeyReader.isEncrypted(readKey("ed25519_encrypted")))
    }

    @Test
    fun `detects unencrypted PEM key`() {
        assertFalse(PrivateKeyReader.isEncrypted(readKey("rsa_pem_unencrypted.pem")))
    }

    @Test
    fun `detects encrypted PEM key`() {
        assertTrue(PrivateKeyReader.isEncrypted(readKey("rsa_pem_encrypted.pem")))
    }

    @Test
    fun `detects unencrypted PKCS8 key`() {
        assertFalse(PrivateKeyReader.isEncrypted(readKey("rsa_pkcs8.pem")))
    }

    // Error cases

    @Test
    fun `rejects unknown format`() {
        assertFailsWith<SshException> {
            PrivateKeyReader.read("not a key at all")
        }
    }

    @Test
    fun `rejects wrong passphrase for OpenSSH key`() {
        assertFailsWith<SshException> {
            PrivateKeyReader.read(readKey("ed25519_encrypted"), "wrongpass")
        }
    }
}
