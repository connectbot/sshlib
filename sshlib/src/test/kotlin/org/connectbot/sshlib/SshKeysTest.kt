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

package org.connectbot.sshlib

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SshKeysTest {

    private fun readKey(resourcePath: String): String {
        return javaClass.getResourceAsStream("/keys/$resourcePath")!!
            .bufferedReader().readText()
    }

    @Test
    fun `decodePemPrivateKey Ed25519 OpenSSH format`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ed25519_unencrypted"))
        assertNotNull(keyPair.public)
        assertNotNull(keyPair.private)
        assertTrue(keyPair.public.algorithm in listOf("Ed25519", "EdDSA"))
    }

    @Test
    fun `decodePemPrivateKey Ed25519 encrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ed25519_encrypted"), "testpass")
        assertNotNull(keyPair.public)
        assertNotNull(keyPair.private)
    }

    @Test
    fun `decodePemPrivateKey ECDSA-256 OpenSSH format`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ecdsa256_unencrypted"))
        assertNotNull(keyPair.public)
        assertEquals("EC", keyPair.public.algorithm)
    }

    @Test
    fun `decodePemPrivateKey ECDSA-256 encrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ecdsa256_encrypted"), "testpass")
        assertNotNull(keyPair.public)
    }

    @Test
    fun `decodePemPrivateKey RSA OpenSSH format`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("rsa_unencrypted"))
        assertNotNull(keyPair.public)
        assertEquals("RSA", keyPair.public.algorithm)
    }

    @Test
    fun `decodePemPrivateKey RSA encrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("rsa_encrypted"), "testpass")
        assertNotNull(keyPair.public)
    }

    @Test
    fun `decodePemPrivateKey RSA PEM unencrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("rsa_pem_unencrypted.pem"))
        assertNotNull(keyPair.public)
        assertEquals("RSA", keyPair.public.algorithm)
    }

    @Test
    fun `decodePemPrivateKey RSA PEM encrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("rsa_pem_encrypted.pem"), "testpass")
        assertNotNull(keyPair.public)
    }

    @Test
    fun `decodePemPrivateKey EC PEM unencrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ec_pem_unencrypted.pem"))
        assertNotNull(keyPair.public)
        assertEquals("EC", keyPair.public.algorithm)
    }

    @Test
    fun `decodePemPrivateKey EC PEM encrypted`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ec_pem_encrypted.pem"), "testpass")
        assertNotNull(keyPair.public)
    }

    @Test
    fun `decodePemPrivateKey Ed25519 PKCS8`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ed25519_pkcs8.pem"))
        assertNotNull(keyPair.public)
    }

    @Test
    fun `decodePemPrivateKey RSA PKCS8`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("rsa_pkcs8.pem"))
        assertNotNull(keyPair.public)
        assertEquals("RSA", keyPair.public.algorithm)
    }

    @Test
    fun `decodePemPrivateKey EC PKCS8`() {
        val keyPair = SshKeys.decodePemPrivateKey(readKey("ec_pkcs8.pem"))
        assertNotNull(keyPair.public)
        assertEquals("EC", keyPair.public.algorithm)
    }

    @Test(expected = SshException::class)
    fun `decodePemPrivateKey invalid data throws`() {
        SshKeys.decodePemPrivateKey("not a valid key")
    }

    @Test
    fun `ensureEd25519Support does not throw`() {
        SshKeys.ensureEd25519Support()
    }

    @Test
    fun `encodePemPrivateKey round-trip Ed25519`() {
        val original = SshKeys.decodePemPrivateKey(readKey("ed25519_unencrypted"))
        val encoded = SshKeys.encodePemPrivateKey(original)
        val decoded = SshKeys.decodePemPrivateKey(encoded)
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encodePemPrivateKey round-trip RSA`() {
        val original = SshKeys.decodePemPrivateKey(readKey("rsa_unencrypted"))
        val encoded = SshKeys.encodePemPrivateKey(original)
        val decoded = SshKeys.decodePemPrivateKey(encoded)
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encodePemPrivateKey round-trip ECDSA`() {
        val original = SshKeys.decodePemPrivateKey(readKey("ecdsa256_unencrypted"))
        val encoded = SshKeys.encodePemPrivateKey(original)
        val decoded = SshKeys.decodePemPrivateKey(encoded)
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encodeOpenSshPrivateKey round-trip Ed25519`() {
        val original = SshKeys.decodePemPrivateKey(readKey("ed25519_unencrypted"))
        val encoded = SshKeys.encodeOpenSshPrivateKey(original)
        assertTrue(encoded.contains("BEGIN OPENSSH PRIVATE KEY"))
        val decoded = SshKeys.decodePemPrivateKey(encoded)
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encodeOpenSshPrivateKey round-trip RSA`() {
        val original = SshKeys.decodePemPrivateKey(readKey("rsa_unencrypted"))
        val encoded = SshKeys.encodeOpenSshPrivateKey(original)
        val decoded = SshKeys.decodePemPrivateKey(encoded)
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encodeOpenSshPrivateKey round-trip ECDSA`() {
        val original = SshKeys.decodePemPrivateKey(readKey("ecdsa256_unencrypted"))
        val encoded = SshKeys.encodeOpenSshPrivateKey(original)
        val decoded = SshKeys.decodePemPrivateKey(encoded)
        assertEquals(original.public, decoded.public)
    }

    @Test
    fun `encodeOpenSshPrivateKey encrypted round-trip`() {
        val original = SshKeys.decodePemPrivateKey(readKey("ed25519_unencrypted"))
        val encoded = SshKeys.encodeOpenSshPrivateKey(original, "mypassword")
        val decoded = SshKeys.decodePemPrivateKey(encoded, "mypassword")
        assertEquals(original.public, decoded.public)
    }
}
