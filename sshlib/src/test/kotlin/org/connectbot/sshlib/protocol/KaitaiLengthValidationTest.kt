/*
 * ConnectBot SSH Library
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

package org.connectbot.sshlib.protocol

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStream
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class KaitaiLengthValidationTest {
    private val hugeLength = byteArrayOf(0x40, 0x00, 0x00, 0x00)
    private val hugeCount = byteArrayOf(0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())

    @Test
    fun `ascii string rejects length larger than containing stream`() {
        assertValidationFailure { AsciiString(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `utf8 string rejects length larger than containing stream`() {
        assertValidationFailure { Utf8String(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `mpint rejects length larger than containing stream`() {
        assertValidationFailure { Mpint(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `name list rejects length larger than containing stream`() {
        assertValidationFailure { NameList(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `public key rejects algorithm length larger than containing stream`() {
        assertValidationFailure { SshPublicKey(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `signature rejects algorithm length larger than containing stream`() {
        assertValidationFailure { SshSignature(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `ecdsa signature rejects blob length larger than containing stream`() {
        assertValidationFailure { EcdsaSignatureBlob(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `etm mac rejects packet length larger than containing stream`() {
        val data = byteArrayOf(0, 0, 0, 0) + hugeLength
        assertValidationFailure { EtmMac(ByteBufferKaitaiStream(data))._read() }
    }

    @Test
    fun `encrypted packet rejects payload length larger than containing stream`() {
        assertValidationFailure { EncryptedPacket(ByteBufferKaitaiStream(hugeLength), 32)._read() }
    }

    @Test
    fun `encrypted packet allows another packet in containing stream`() {
        val firstPayload = byteArrayOf(1, 2, 3, 4)
        val secondPayload = byteArrayOf(5, 6, 7, 8)
        val mac = ByteArray(4)
        val data = lengthPrefix(firstPayload.size) + firstPayload + mac +
            lengthPrefix(secondPayload.size) + secondPayload + mac
        val stream = ByteBufferKaitaiStream(data)

        val first = EncryptedPacket(stream, mac.size.toLong()).also { it._read() }
        val second = EncryptedPacket(stream, mac.size.toLong()).also { it._read() }

        assertContentEquals(firstPayload, first.encryptedPayload())
        assertContentEquals(secondPayload, second.encryptedPayload())
    }

    @Test
    fun `unencrypted packet rejects packet length larger than containing stream`() {
        assertValidationFailure { UnencryptedPacket(ByteBufferKaitaiStream(hugeLength))._read() }
    }

    @Test
    fun `unencrypted packet rejects padding that leaves no message type`() {
        val data = byteArrayOf(
            0,
            0,
            0,
            6,
            5,
            0,
            0,
            0,
            0,
            0,
        )
        assertValidationFailure { UnencryptedPacket(ByteBufferKaitaiStream(data))._read() }
    }

    @Test
    fun `ext info rejects impossible extension count`() {
        assertValidationFailure { SshMsgExtInfo(ByteBufferKaitaiStream(hugeCount))._read() }
    }

    @Test
    fun `keyboard interactive request rejects impossible prompt count`() {
        val data = emptyByteString() + emptyByteString() + emptyByteString() + hugeCount
        assertValidationFailure { SshMsgUserauthInfoRequest(ByteBufferKaitaiStream(data))._read() }
    }

    @Test
    fun `keyboard interactive response rejects impossible response count`() {
        assertValidationFailure { SshMsgUserauthInfoResponse(ByteBufferKaitaiStream(hugeCount))._read() }
    }

    @Test
    fun `gssapi request rejects impossible mechanism count`() {
        assertValidationFailure { UserauthRequestGssapiWithMic(ByteBufferKaitaiStream(hugeCount))._read() }
    }

    @Test
    fun `agent identities rejects impossible key count`() {
        assertValidationFailure { SshAgentIdentitiesAnswer(ByteBufferKaitaiStream(hugeCount))._read() }
    }

    @Test
    fun `destination constraint rejects impossible from keyspec count`() {
        val data = emptyByteString() + hugeCount
        assertValidationFailure { RestrictDestinationConstraint(ByteBufferKaitaiStream(data))._read() }
    }

    private fun emptyByteString(): ByteArray = byteArrayOf(0, 0, 0, 0)

    private fun lengthPrefix(length: Int): ByteArray = byteArrayOf(
        (length ushr 24).toByte(),
        (length ushr 16).toByte(),
        (length ushr 8).toByte(),
        length.toByte(),
    )

    private fun assertValidationFailure(block: () -> Unit) {
        val error = assertFailsWith<RuntimeException> { block() }
        check(error is KaitaiStream.ValidationExprError) {
            "Expected ValidationExprError but got ${error::class.qualifiedName}"
        }
    }
}
