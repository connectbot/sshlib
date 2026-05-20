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

package org.connectbot.sshlib.transport

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.crypto.AesCbcCipher
import org.connectbot.sshlib.crypto.AesCtrCipher
import org.connectbot.sshlib.crypto.HmacSha256
import org.connectbot.sshlib.crypto.TripleDesCbcCipher
import org.connectbot.sshlib.protocol.SshEnums
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class PacketIOEtmTest {

    private fun createKeyMaterial(): Triple<ByteArray, ByteArray, ByteArray> {
        val cipherKey = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it + 0x10).toByte() }
        val macKey = ByteArray(32) { (it + 0x20).toByte() }
        return Triple(cipherKey, iv, macKey)
    }

    @Test
    fun `ETM round trip with AES-CBC`() = runBlocking {
        val (cipherKey, iv, macKey) = createKeyMaterial()

        val writeTransport = ByteArrayTransport()
        val writeIO = PacketIO(writeTransport)
        writeIO.enableEncryption(
            clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        writeIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt())

        val wireData = writeTransport.getWrittenData()

        val readTransport = ByteArrayTransport(wireData)
        val readIO = PacketIO(readTransport)
        readIO.enableEncryption(
            clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        val parsed = readIO.readPacket()
        assertEquals(SshEnums.MessageType.SSH_MSG_NEWKEYS, parsed.messageType())
    }

    @Test
    fun `ETM round trip with AES-CTR`() = runBlocking {
        val (cipherKey, iv, macKey) = createKeyMaterial()

        val writeTransport = ByteArrayTransport()
        val writeIO = PacketIO(writeTransport)
        writeIO.enableEncryption(
            clientToServerCipher = AesCtrCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCtrCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        writeIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt())

        val wireData = writeTransport.getWrittenData()

        val readTransport = ByteArrayTransport(wireData)
        val readIO = PacketIO(readTransport)
        readIO.enableEncryption(
            clientToServerCipher = AesCtrCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCtrCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        val parsed = readIO.readPacket()
        assertEquals(SshEnums.MessageType.SSH_MSG_NEWKEYS, parsed.messageType())
    }

    @Test
    fun `ETM encrypted payload is block-aligned with CBC`() = runBlocking {
        val (cipherKey, iv, macKey) = createKeyMaterial()
        val blockSize = 16

        for (payloadSize in 0..64) {
            val writeTransport = ByteArrayTransport()
            val writeIO = PacketIO(writeTransport)
            writeIO.enableEncryption(
                clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
                clientToServerMac = HmacSha256(macKey.copyOf()),
                serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
                serverToClientMac = HmacSha256(macKey.copyOf()),
                clientToServerEtm = true,
                serverToClientEtm = true,
            )

            val payload = ByteArray(payloadSize)
            writeIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt(), payload)

            val wireData = writeTransport.getWrittenData()
            val encryptedPayloadSize = wireData.size - 4 - 32
            assertEquals(
                0,
                encryptedPayloadSize % blockSize,
                "Encrypted payload not block-aligned for payloadSize=$payloadSize",
            )
        }
    }

    @Test
    fun `ETM round trip with 3DES-CBC`() = runBlocking {
        val tripleDesKey = ByteArray(24) { it.toByte() }
        val tripleDesIv = ByteArray(8) { (it + 0x10).toByte() }
        val macKey = ByteArray(32) { (it + 0x20).toByte() }

        val writeTransport = ByteArrayTransport()
        val writeIO = PacketIO(writeTransport)
        writeIO.enableEncryption(
            clientToServerCipher = TripleDesCbcCipher(tripleDesKey, tripleDesIv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = TripleDesCbcCipher(tripleDesKey, tripleDesIv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        writeIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt())

        val wireData = writeTransport.getWrittenData()

        // Verify encrypted payload is 8-byte aligned (3DES block size)
        val encryptedPayloadSize = wireData.size - 4 - 32
        assertEquals(0, encryptedPayloadSize % 8)

        val readTransport = ByteArrayTransport(wireData)
        val readIO = PacketIO(readTransport)
        readIO.enableEncryption(
            clientToServerCipher = TripleDesCbcCipher(tripleDesKey, tripleDesIv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = TripleDesCbcCipher(tripleDesKey, tripleDesIv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        val parsed = readIO.readPacket()
        assertEquals(SshEnums.MessageType.SSH_MSG_NEWKEYS, parsed.messageType())
    }

    @Test
    fun `ETM multiple packets round trip with CBC`() = runBlocking {
        val (cipherKey, iv, macKey) = createKeyMaterial()

        val writeTransport = ByteArrayTransport()
        val writeIO = PacketIO(writeTransport)
        writeIO.enableEncryption(
            clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        val messageType = SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt()
        writeIO.writePacket(messageType)
        writeIO.writePacket(messageType)
        writeIO.writePacket(messageType)

        val wireData = writeTransport.getWrittenData()

        val readTransport = ByteArrayTransport(wireData)
        val readIO = PacketIO(readTransport)
        readIO.enableEncryption(
            clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
            clientToServerEtm = true,
            serverToClientEtm = true,
        )

        for (i in 1..3) {
            val parsed = readIO.readPacket()
            assertEquals(SshEnums.MessageType.SSH_MSG_NEWKEYS, parsed.messageType())
        }
    }
}
