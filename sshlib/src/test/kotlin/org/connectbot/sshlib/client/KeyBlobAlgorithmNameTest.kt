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

package org.connectbot.sshlib.client

import org.connectbot.sshlib.SshSigning
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class KeyBlobAlgorithmNameTest {

    private fun readKey(resourcePath: String): String = javaClass.getResourceAsStream("/keys/$resourcePath")!!.bufferedReader().readText()

    /** Builds a minimal blob: 4-byte big-endian length prefix + ASCII name bytes. */
    private fun blobWithName(name: String): ByteArray {
        val nameBytes = name.toByteArray(Charsets.US_ASCII)
        val len = nameBytes.size
        return byteArrayOf(
            (len ushr 24).toByte(),
            (len ushr 16).toByte(),
            (len ushr 8).toByte(),
            len.toByte(),
        ) + nameBytes
    }

    @Test
    fun `returns null for empty blob`() {
        assertNull(keyBlobAlgorithmName(byteArrayOf()))
    }

    @Test
    fun `returns null for blob shorter than 4 bytes`() {
        assertNull(keyBlobAlgorithmName(byteArrayOf(0, 0, 0)))
    }

    @Test
    fun `returns null when length field is zero`() {
        assertNull(keyBlobAlgorithmName(byteArrayOf(0, 0, 0, 0, 'x'.code.toByte())))
    }

    @Test
    fun `returns null when length exceeds available bytes`() {
        // length field says 5 but only 3 bytes follow
        assertNull(keyBlobAlgorithmName(byteArrayOf(0, 0, 0, 5, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte())))
    }

    @Test
    fun `returns null when length is one more than available bytes`() {
        // length = 4, only 3 bytes of name data — kills ConditionalsBoundaryMutator on len > size-4
        val blob = byteArrayOf(0, 0, 0, 4, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte())
        assertNull(keyBlobAlgorithmName(blob))
    }

    @Test
    fun `decodes when length exactly equals available bytes`() {
        // length = 3, exactly 3 bytes follow — boundary passes, name is returned
        val blob = byteArrayOf(0, 0, 0, 3, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte())
        assertEquals("abc", keyBlobAlgorithmName(blob))
    }

    @Test
    fun `decodes ssh-ed25519 blob from real key`() {
        val blob = SshSigning.getPublicKey("ssh-ed25519", readKey("ed25519_unencrypted"), null).publicKeyBlob
        assertEquals("ssh-ed25519", keyBlobAlgorithmName(blob))
    }

    @Test
    fun `decodes ssh-rsa blob from real key`() {
        val blob = SshSigning.getPublicKey("ssh-rsa", readKey("rsa_unencrypted"), null).publicKeyBlob
        assertEquals("ssh-rsa", keyBlobAlgorithmName(blob))
    }

    @Test
    fun `decodes ecdsa-sha2-nistp256 blob from real key`() {
        val blob = SshSigning.getPublicKey("ecdsa-sha2-nistp256", readKey("ecdsa256_unencrypted"), null).publicKeyBlob
        assertEquals("ecdsa-sha2-nistp256", keyBlobAlgorithmName(blob))
    }
}
