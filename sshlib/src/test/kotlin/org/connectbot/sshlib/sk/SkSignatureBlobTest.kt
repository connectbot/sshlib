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
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class SkSignatureBlobTest {

    // ---------------------- Ed25519 ----------------------

    @Test
    fun `packs Ed25519 signature blob byte-exact`() {
        val rawSig = ByteArray(64) { i -> (0xA0 + (i and 0x0f)).toByte() }
        val flags: Byte = SkSignatureBlob.FLAG_USER_PRESENCE
        val counter: UInt = 0x12345678u

        val blob = SkSignatureBlob.pack(SkAlgorithm.ED25519, rawSig, flags, counter)

        val expected = sshString("sk-ssh-ed25519@openssh.com".toByteArray()) +
            sshString(rawSig) +
            byteArrayOf(flags) +
            byteArrayOf(0x12, 0x34, 0x56, 0x78)
        assertContentEquals(expected, blob)
    }

    @Test
    fun `Ed25519 flags accumulate UP and UV bits`() {
        val rawSig = ByteArray(64)
        val combinedFlags = (SkSignatureBlob.FLAG_USER_PRESENCE.toInt() or SkSignatureBlob.FLAG_USER_VERIFICATION.toInt()).toByte()
        val blob = SkSignatureBlob.pack(SkAlgorithm.ED25519, rawSig, combinedFlags, 1u)
        // Flag byte is at: 4 + 26 (algo string len-prefix + algo) + 4 + 64 (sig string len-prefix + sig) = 98
        val flagOffset = 4 + 26 + 4 + 64
        assertContentEquals(byteArrayOf(0x05), blob.copyOfRange(flagOffset, flagOffset + 1))
    }

    @Test
    fun `rejects wrong-sized Ed25519 raw signature`() {
        assertFailsWith<SshException> {
            SkSignatureBlob.pack(SkAlgorithm.ED25519, ByteArray(63), 0x01, 1u)
        }
        assertFailsWith<SshException> {
            SkSignatureBlob.pack(SkAlgorithm.ED25519, ByteArray(65), 0x01, 1u)
        }
    }

    @Test
    fun `Ed25519 counter wraps at uint32 boundary correctly`() {
        val rawSig = ByteArray(64)
        val blob = SkSignatureBlob.pack(SkAlgorithm.ED25519, rawSig, 0x01, UInt.MAX_VALUE)
        // Last 4 bytes = 0xFF 0xFF 0xFF 0xFF
        assertContentEquals(byteArrayOf(-1, -1, -1, -1), blob.copyOfRange(blob.size - 4, blob.size))
    }

    // ---------------------- ECDSA-P256 ----------------------

    @Test
    fun `packs ECDSA-P256 with small r and s (no high-bit padding)`() {
        // DER: SEQUENCE { INTEGER 0x12, INTEGER 0x34 } = 30 06 02 01 12 02 01 34
        val der = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x12, 0x02, 0x01, 0x34)

        val blob = SkSignatureBlob.pack(SkAlgorithm.ECDSA_P256, der, 0x01, 0x00000001u)

        // sig_material = mpint(0x12) || mpint(0x34)
        //              = (00 00 00 01 12) || (00 00 00 01 34)
        //              = 00 00 00 01 12 00 00 00 01 34   (10 bytes)
        val sigMaterial = byteArrayOf(
            0x00, 0x00, 0x00, 0x01, 0x12,
            0x00, 0x00, 0x00, 0x01, 0x34,
        )
        val expected = sshString("sk-ecdsa-sha2-nistp256@openssh.com".toByteArray()) +
            sshString(sigMaterial) +
            byteArrayOf(0x01) +
            byteArrayOf(0x00, 0x00, 0x00, 0x01)
        assertContentEquals(expected, blob)
    }

    @Test
    fun `packs ECDSA-P256 where r needs mpint zero-padding (high bit set)`() {
        // r = 32 bytes with high bit set => DER adds leading 0x00 to keep it positive (33 bytes total)
        // s = 32 bytes with high bit clear => DER body is exactly 32 bytes
        val rBytes = ByteArray(32) { i -> if (i == 0) 0x80.toByte() else (0x01 + i).toByte() }
        val sBytes = ByteArray(32) { i -> if (i == 0) 0x01 else (0x10 + i).toByte() }

        val rDerBody = byteArrayOf(0x00) + rBytes // 33 bytes
        val sDerBody = sBytes // 32 bytes
        val der = byteArrayOf(0x30, (rDerBody.size + 2 + sDerBody.size + 2).toByte()) +
            byteArrayOf(0x02, rDerBody.size.toByte()) + rDerBody +
            byteArrayOf(0x02, sDerBody.size.toByte()) + sDerBody

        val blob = SkSignatureBlob.pack(SkAlgorithm.ECDSA_P256, der, 0x01, 7u)

        // mpint(r) needs leading 0x00 because r's high bit is set: length-prefix=33, body=00||rBytes
        // mpint(s) has high bit clear: length-prefix=32, body=sBytes
        val expectedSigMaterial = byteArrayOf(0x00, 0x00, 0x00, 0x21, 0x00) + rBytes +
            byteArrayOf(0x00, 0x00, 0x00, 0x20) + sBytes
        val expected = sshString("sk-ecdsa-sha2-nistp256@openssh.com".toByteArray()) +
            sshString(expectedSigMaterial) +
            byteArrayOf(0x01) +
            byteArrayOf(0x00, 0x00, 0x00, 0x07)
        assertContentEquals(expected, blob)
    }

    @Test
    fun `packs ECDSA-P256 mpint conversion is round-trip-stable via BigInteger`() {
        // Build a DER with two random-ish 256-bit values, pack, then parse the mpints
        // back out and confirm BigInteger equality.
        val r = BigInteger("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210", 16)
        val s = BigInteger("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", 16)
        val der = makeDerEcdsaSignature(r, s)

        val blob = SkSignatureBlob.pack(SkAlgorithm.ECDSA_P256, der, 0x05, 99u)

        // Skip past algo-string to the sig string (which contains mpint r || mpint s)
        val algoLen = "sk-ecdsa-sha2-nistp256@openssh.com".length
        val sigStringOffset = 4 + algoLen
        val sigStringLen = readUint32(blob, sigStringOffset)
        val sigMaterial = blob.copyOfRange(sigStringOffset + 4, sigStringOffset + 4 + sigStringLen)

        // Parse mpint r, mpint s
        val rLen = readUint32(sigMaterial, 0)
        val rOut = BigInteger(1, sigMaterial.copyOfRange(4, 4 + rLen))
        val sLen = readUint32(sigMaterial, 4 + rLen)
        val sOut = BigInteger(1, sigMaterial.copyOfRange(4 + rLen + 4, 4 + rLen + 4 + sLen))

        kotlin.test.assertEquals(r, rOut)
        kotlin.test.assertEquals(s, sOut)
    }

    @Test
    fun `rejects malformed DER for ECDSA`() {
        // Empty bytes
        assertFailsWith<SshException> {
            SkSignatureBlob.pack(SkAlgorithm.ECDSA_P256, ByteArray(0), 0x01, 1u)
        }
        // Not a SEQUENCE
        assertFailsWith<SshException> {
            SkSignatureBlob.pack(SkAlgorithm.ECDSA_P256, byteArrayOf(0x04, 0x00), 0x01, 1u)
        }
        // SEQUENCE missing one INTEGER
        assertFailsWith<SshException> {
            SkSignatureBlob.pack(
                SkAlgorithm.ECDSA_P256,
                byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x12),
                0x01,
                1u,
            )
        }
    }

    // ---------------------- helpers ----------------------

    /** Build DER `SEQUENCE { INTEGER r, INTEGER s }` from two non-negative BigIntegers. */
    private fun makeDerEcdsaSignature(r: BigInteger, s: BigInteger): ByteArray {
        val rTlv = derInteger(r)
        val sTlv = derInteger(s)
        val content = rTlv + sTlv
        return byteArrayOf(0x30) + derLength(content.size) + content
    }

    private fun derInteger(value: BigInteger): ByteArray {
        val body = value.toByteArray() // BigInteger.toByteArray() already adds leading 0x00 if high bit set
        return byteArrayOf(0x02) + derLength(body.size) + body
    }

    private fun derLength(length: Int): ByteArray {
        if (length < 0x80) return byteArrayOf(length.toByte())
        // Short-form sufficient for our test sizes
        if (length < 0x100) return byteArrayOf(0x81.toByte(), length.toByte())
        return byteArrayOf(0x82.toByte(), (length ushr 8).toByte(), length.toByte())
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

    private fun readUint32(buf: ByteArray, offset: Int): Int = ((buf[offset].toInt() and 0xff) shl 24) or
        ((buf[offset + 1].toInt() and 0xff) shl 16) or
        ((buf[offset + 2].toInt() and 0xff) shl 8) or
        (buf[offset + 3].toInt() and 0xff)
}
