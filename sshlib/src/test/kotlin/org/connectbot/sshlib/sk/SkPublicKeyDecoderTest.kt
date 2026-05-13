/*
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

package org.connectbot.sshlib.sk

import org.connectbot.sshlib.SshException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SkPublicKeyDecoderTest {

    @Test
    fun `round-trips Ed25519 SK public key`() {
        val original = SkPublicKey(
            algorithm = SkAlgorithm.ED25519,
            rawKey = ByteArray(32) { it.toByte() },
            application = "ssh:",
        )
        val blob = SkPublicKeyEncoder.encode(original.algorithm, original.rawKey, original.application)
        val decoded = SkPublicKeyDecoder.decode(blob)
        assertEquals(original, decoded)
    }

    @Test
    fun `round-trips ECDSA-P256 SK public key`() {
        val ecPoint = ByteArray(65).also {
            it[0] = 0x04
            for (i in 1..64) it[i] = i.toByte()
        }
        val original = SkPublicKey(
            algorithm = SkAlgorithm.ECDSA_P256,
            rawKey = ecPoint,
            application = "ssh:my-rp",
        )
        val blob = SkPublicKeyEncoder.encode(original.algorithm, original.rawKey, original.application)
        val decoded = SkPublicKeyDecoder.decode(blob)
        assertEquals(original.algorithm, decoded.algorithm)
        assertContentEquals(original.rawKey, decoded.rawKey)
        assertEquals(original.application, decoded.application)
    }

    @Test
    fun `rejects unknown algorithm name`() {
        val blob = sshString("ssh-ed25519".toByteArray()) + sshString(ByteArray(32))
        val e = assertFailsWith<SshException> { SkPublicKeyDecoder.decode(blob) }
        assert(e.message!!.contains("ssh-ed25519")) { "expected algo name in error: ${e.message}" }
    }

    @Test
    fun `rejects truncated blob`() {
        val blob = sshString("sk-ssh-ed25519@openssh.com".toByteArray()) + sshString(ByteArray(16)) // wrong size
        assertFailsWith<SshException> { SkPublicKeyDecoder.decode(blob) }
    }

    @Test
    fun `rejects trailing bytes`() {
        val good = SkPublicKeyEncoder.encode(SkAlgorithm.ED25519, ByteArray(32), "ssh:")
        val withTrailing = good + byteArrayOf(0x01, 0x02, 0x03)
        assertFailsWith<SshException> { SkPublicKeyDecoder.decode(withTrailing) }
    }

    @Test
    fun `rejects ECDSA blob with wrong curve identifier`() {
        val ecPoint = ByteArray(65).also { it[0] = 0x04 }
        val blob = sshString("sk-ecdsa-sha2-nistp256@openssh.com".toByteArray()) +
            sshString("nistp384".toByteArray()) +
            sshString(ecPoint) +
            sshString("ssh:".toByteArray())
        val e = assertFailsWith<SshException> { SkPublicKeyDecoder.decode(blob) }
        assert(e.message!!.contains("nistp")) { "expected curve mismatch error: ${e.message}" }
    }

    private fun sshString(bytes: ByteArray): ByteArray {
        val len = bytes.size
        return byteArrayOf(
            (len ushr 24).toByte(),
            (len ushr 16).toByte(),
            (len ushr 8).toByte(),
            len.toByte(),
        ) + bytes
    }
}
