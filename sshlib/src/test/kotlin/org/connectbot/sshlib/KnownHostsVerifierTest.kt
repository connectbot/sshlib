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

package org.connectbot.sshlib

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PublicKeyTest {

    @Test
    fun `equal when type and encoded are the same`() {
        val k1 = PublicKey("ssh-rsa", byteArrayOf(1, 2, 3))
        val k2 = PublicKey("ssh-rsa", byteArrayOf(1, 2, 3))
        assertEquals(k1, k2)
        assertEquals(k1.hashCode(), k2.hashCode())
    }

    @Test
    fun `not equal when type differs`() {
        val k1 = PublicKey("ssh-rsa", byteArrayOf(1, 2, 3))
        val k2 = PublicKey("ssh-ed25519", byteArrayOf(1, 2, 3))
        assertNotEquals(k1, k2)
    }

    @Test
    fun `not equal when encoded differs`() {
        val k1 = PublicKey("ssh-rsa", byteArrayOf(1, 2, 3))
        val k2 = PublicKey("ssh-rsa", byteArrayOf(1, 2, 4))
        assertNotEquals(k1, k2)
    }

    @Test
    fun `self-equality`() {
        val k = PublicKey("ssh-rsa", byteArrayOf(1))
        assertEquals(k, k)
    }

    @Test
    fun `not equal to different type`() {
        val k = PublicKey("ssh-rsa", byteArrayOf(1))
        assertFalse(k.equals("not a key"))
    }

    @Test
    fun `hashCode differs when type differs`() {
        val k1 = PublicKey("ssh-rsa", byteArrayOf(1, 2))
        val k2 = PublicKey("ssh-dss", byteArrayOf(1, 2))
        assertNotEquals(k1.hashCode(), k2.hashCode())
    }

    @Test
    fun `hashCode differs when encoded differs`() {
        val k1 = PublicKey("ssh-rsa", byteArrayOf(1))
        val k2 = PublicKey("ssh-rsa", byteArrayOf(2))
        assertNotEquals(k1.hashCode(), k2.hashCode())
    }
}

class KnownHostsVerifierTest {

    @TempDir
    lateinit var tempDir: Path

    private fun makeFile(content: String): File {
        val file = tempDir.resolve("known_hosts_${System.nanoTime()}").toFile()
        file.writeText(content)
        return file
    }

    private fun base64(data: ByteArray) = Base64.getEncoder().encodeToString(data)

    @Test
    fun `verifies exact match`() = runTest {
        val keyData = ByteArray(32) { it.toByte() }
        val file = makeFile("example.com ssh-rsa ${base64(keyData)}")

        val key = PublicKey("ssh-rsa", keyData)

        val verifier = KnownHostsVerifier(file, "example.com")
        assertTrue(verifier.verify(key))

        val otherVerifier = KnownHostsVerifier(file, "other.com")
        assertFalse(otherVerifier.verify(key))
    }

    @Test
    fun `verifies wildcard match`() = runTest {
        val keyData = ByteArray(32) { 1 }
        val file = makeFile("*.example.com ssh-rsa ${base64(keyData)}")

        val key = PublicKey("ssh-rsa", keyData)

        val subVerifier = KnownHostsVerifier(file, "sub.example.com")
        assertTrue(subVerifier.verify(key))

        val exactVerifier = KnownHostsVerifier(file, "example.com")
        assertFalse(exactVerifier.verify(key))
    }

    @Test
    fun `verifies with port`() = runTest {
        val keyData = ByteArray(32) { 2 }
        val file = makeFile("[example.com]:2222 ssh-rsa ${base64(keyData)}")

        val key = PublicKey("ssh-rsa", keyData)

        val portVerifier = KnownHostsVerifier(file, "example.com", 2222)
        assertTrue(portVerifier.verify(key))

        val defaultPortVerifier = KnownHostsVerifier(file, "example.com")
        assertFalse(defaultPortVerifier.verify(key))
    }

    @Test
    fun `rejects incorrect key`() = runTest {
        val keyData1 = ByteArray(32) { 1 }
        val file = makeFile("example.com ssh-rsa ${base64(keyData1)}")

        val verifier = KnownHostsVerifier(file, "example.com")
        val key2 = PublicKey("ssh-rsa", ByteArray(32) { 2 })

        assertFalse(verifier.verify(key2))
    }

    @Test
    fun `returns false for non-existent file`() = runTest {
        val file = tempDir.resolve("does_not_exist").toFile()
        val verifier = KnownHostsVerifier(file, "example.com")
        assertFalse(verifier.verify(PublicKey("ssh-rsa", ByteArray(32) { 1 })))
    }

    @Test
    fun `skips comment lines`() = runTest {
        val keyData = ByteArray(32) { 1 }
        val file = makeFile("# this is a comment\nexample.com ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "example.com")
        assertTrue(verifier.verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `skips blank lines`() = runTest {
        val keyData = ByteArray(32) { 2 }
        val file = makeFile("\n\nexample.com ssh-rsa ${base64(keyData)}\n")

        val verifier = KnownHostsVerifier(file, "example.com")
        assertTrue(verifier.verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `skips lines with fewer than 3 fields`() = runTest {
        val keyData = ByteArray(32) { 3 }
        val file = makeFile("example.com ssh-rsa\nexample.com ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "example.com")
        assertTrue(verifier.verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `skips lines with invalid base64`() = runTest {
        val keyData = ByteArray(32) { 4 }
        val file = makeFile("example.com ssh-rsa not!valid!base64\nexample.com ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "example.com")
        assertTrue(verifier.verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `hashed host lines are ignored`() = runTest {
        val keyData = ByteArray(32) { 5 }
        val file = makeFile("|1|somesalt|somehash ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "example.com")
        assertFalse(verifier.verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `question mark wildcard matches single character`() = runTest {
        val keyData = ByteArray(32) { 6 }
        val file = makeFile("host?.example.com ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "host1.example.com")
        assertTrue(verifier.verify(PublicKey("ssh-rsa", keyData)))

        val noMatch = KnownHostsVerifier(file, "host12.example.com")
        assertFalse(noMatch.verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `multiple hosts on one line - all are checked`() = runTest {
        val keyData = ByteArray(32) { 7 }
        val file = makeFile("host1.com,host2.com ssh-rsa ${base64(keyData)}")

        assertTrue(KnownHostsVerifier(file, "host1.com").verify(PublicKey("ssh-rsa", keyData)))
        assertTrue(KnownHostsVerifier(file, "host2.com").verify(PublicKey("ssh-rsa", keyData)))
        assertFalse(KnownHostsVerifier(file, "host3.com").verify(PublicKey("ssh-rsa", keyData)))
    }

    @Test
    fun `host known but wrong algorithm type is rejected`() = runTest {
        val keyData = ByteArray(32) { 8 }
        val file = makeFile("example.com ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "example.com")
        assertFalse(verifier.verify(PublicKey("ssh-ed25519", keyData)))
    }

    @Test
    fun `port 22 uses plain hostname format`() = runTest {
        val keyData = ByteArray(32) { 9 }
        val file = makeFile("example.com ssh-rsa ${base64(keyData)}")

        val verifier = KnownHostsVerifier(file, "example.com", 22)
        assertTrue(verifier.verify(PublicKey("ssh-rsa", keyData)))
    }
}
