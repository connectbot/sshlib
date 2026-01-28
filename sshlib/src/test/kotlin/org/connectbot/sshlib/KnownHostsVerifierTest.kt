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

import kotlinx.coroutines.test.runTest
import org.junit.Test
import java.io.File
import java.util.Base64
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KnownHostsVerifierTest {

    @Test
    fun `verifies exact match`() = runTest {
        val file = File.createTempFile("known_hosts", "test")
        try {
            val keyData = ByteArray(32) { it.toByte() }
            val keyBase64 = Base64.getEncoder().encodeToString(keyData)
            val line = "example.com ssh-rsa $keyBase64"
            file.writeText(line)

            val key = PublicKey("ssh-rsa", keyData)

            val verifier = KnownHostsVerifier(file, "example.com")
            assertTrue(verifier.verify(key))

            val otherVerifier = KnownHostsVerifier(file, "other.com")
            assertFalse(otherVerifier.verify(key))
        } finally {
            file.delete()
        }
    }

    @Test
    fun `verifies wildcard match`() = runTest {
        val file = File.createTempFile("known_hosts", "test")
        try {
            val keyData = ByteArray(32) { 1 }
            val keyBase64 = Base64.getEncoder().encodeToString(keyData)
            val line = "*.example.com ssh-rsa $keyBase64"
            file.writeText(line)

            val key = PublicKey("ssh-rsa", keyData)

            val subVerifier = KnownHostsVerifier(file, "sub.example.com")
            assertTrue(subVerifier.verify(key))

            val exactVerifier = KnownHostsVerifier(file, "example.com")
            assertFalse(exactVerifier.verify(key))
        } finally {
            file.delete()
        }
    }

    @Test
    fun `verifies with port`() = runTest {
        val file = File.createTempFile("known_hosts", "test")
        try {
            val keyData = ByteArray(32) { 2 }
            val keyBase64 = Base64.getEncoder().encodeToString(keyData)
            val line = "[example.com]:2222 ssh-rsa $keyBase64"
            file.writeText(line)

            val key = PublicKey("ssh-rsa", keyData)

            val portVerifier = KnownHostsVerifier(file, "example.com", 2222)
            assertTrue(portVerifier.verify(key))

            val defaultPortVerifier = KnownHostsVerifier(file, "example.com")
            assertFalse(defaultPortVerifier.verify(key))
        } finally {
            file.delete()
        }
    }

    @Test
    fun `rejects incorrect key`() = runTest {
        val file = File.createTempFile("known_hosts", "test")
        try {
            val keyData1 = ByteArray(32) { 1 }
            val keyBase64 = Base64.getEncoder().encodeToString(keyData1)
            val line = "example.com ssh-rsa $keyBase64"
            file.writeText(line)

            val verifier = KnownHostsVerifier(file, "example.com")
            val key2 = PublicKey("ssh-rsa", ByteArray(32) { 2 })

            assertFalse(verifier.verify(key2))
        } finally {
            file.delete()
        }
    }
}
