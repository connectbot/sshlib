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

package org.connectbot.sshlib.protocol

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.transport.ByteArrayTransport
import org.connectbot.sshlib.transport.PacketIO
import org.junit.jupiter.api.Test
import java.math.BigInteger
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Tests that parse captured SSH protocol data.
 *
 * These tests demonstrate:
 * 1. Using ByteArrayTransport to feed captured bytes into the library
 * 2. Parsing unencrypted SSH packets via PacketIO
 * 3. Manual decryption of ETM (Encrypt-then-MAC) encrypted packets
 *
 * The captured data uses ETM mode which is different from the standard
 * encrypt-and-MAC mode currently in PacketIO, so encrypted packets are
 * parsed manually using the derived keys from the capture.
 */
class CaptureTest {

    /**
     * Parse the server-to-client capture file using ByteArrayTransport and PacketIO.
     */
    @Test
    fun `parse unencrypted packets via PacketIO`() = runBlocking {
        val captureData = loadCaptureFile("server-to-client.cap")
        val transport = ByteArrayTransport(captureData)
        val packetIO = PacketIO(transport)

        // Read banner
        val banner = packetIO.readBanner()
        println("Banner: ${banner.protoVersion().trimEnd('\r', '\n')}")
        assertTrue(banner.protoVersion().startsWith("2.0"))

        // Read unencrypted packets until NEWKEYS
        var packetCount = 0
        while (true) {
            val packet = packetIO.readPacket()
            packetCount++
            println("Packet $packetCount: ${packet.messageType()}")

            when (packet.messageType()) {
                SshEnums.MessageType.SSH_MSG_KEXINIT -> {
                    val kexInit = packet.body() as SshMsgKexinit
                    println("  KEX algorithms: ${kexInit.kexAlgorithms().entries().data()}")
                    println("  Host key algorithms: ${kexInit.serverHostKeyAlgorithms().entries().data()}")
                }

                SshEnums.MessageType.SSH_MSG_NEWKEYS -> {
                    println("  NEWKEYS received - switching to encrypted mode")
                    break
                }

                else -> {
                    // KEX method specific messages need special handling
                    if (packet.messageType().id() in 30..49) {
                        parseKexMethodSpecific(packet)
                    }
                }
            }
        }

        println("\nParsed $packetCount unencrypted packets")
        println("Remaining bytes for encrypted packets: ${transport.bytesRemaining}")

        // The rest of the capture is encrypted with ETM mode
        // We'll parse it manually since PacketIO doesn't support ETM yet
        assertTrue(transport.bytesRemaining > 0)
    }

    /**
     * Parse the full capture including encrypted packets using manual decryption.
     *
     * The capture uses ETM (Encrypt-then-MAC) mode with hardcoded derived keys.
     */
    @Test
    fun `parse full capture with manual ETM decryption`() = runBlocking {
        val captureData = loadCaptureFile("server-to-client.cap")
        val transport = ByteArrayTransport(captureData)
        val packetIO = PacketIO(transport)

        // Read banner
        val banner = packetIO.readBanner()
        assertNotNull(banner)

        // Read unencrypted packets until NEWKEYS
        // Sequence numbers: KEXINIT=1, DH_REPLY=2, NEWKEYS=3
        var seqNum = 1
        while (true) {
            val packet = packetIO.readPacket()
            if (packet.messageType() == SshEnums.MessageType.SSH_MSG_NEWKEYS) {
                break
            }
            seqNum++
        }
        println("After NEWKEYS seqNum=$seqNum")

        // Parse encrypted packets manually using ETM mode
        val iv = INITIAL_IV_S_TO_C.clone()
        var encryptedPacketCount = 0

        // For parsing we need to get the remaining bytes as a stream
        val remainingBytes = transport.read(transport.bytesRemaining)
        val encryptedStream = ByteBufferKaitaiStream(remainingBytes)

        while (!encryptedStream.isEof) {
            encryptedPacketCount++

            // Parse using EncryptedPacket structure
            val msg = EncryptedPacket(encryptedStream, MAC_LENGTH.toLong())
            msg._read()

            // Compute MAC (ETM: sequence_number || len_encrypted_packet || encrypted_packet)
            val computedMac = computeHmacSha256(MAC_KEY, seqNum, msg.lenEncryptedPayload(), msg.encryptedPayload())
            println("Packet $encryptedPacketCount seqNum=$seqNum encLen=${msg.lenEncryptedPayload()}")
            println("  actual MAC: ${BigInteger(1, msg.mac()).toString(16)}")
            println("  computed MAC: ${BigInteger(1, computedMac).toString(16)}")
            assertEquals(
                BigInteger(1, msg.mac()).toString(16),
                BigInteger(1, computedMac).toString(16),
                "MAC verification failed for packet $encryptedPacketCount (seqNum=$seqNum)",
            )

            // Decrypt
            val decrypted = decryptAesCtr(CIPHER_KEY, iv, msg.encryptedPayload())

            // Increment IV by number of blocks
            incrementIv(iv, decrypted.size / AES_BLOCK_SIZE)

            // Parse decrypted packet
            val stream = ByteBufferKaitaiStream(decrypted)
            val decryptedPacket = EncryptedPacket.DecryptedPacket(stream, msg)
            decryptedPacket._read()

            println("Encrypted packet $encryptedPacketCount: ${decryptedPacket.payload().messageType()}")

            when (decryptedPacket.payload().messageType()) {
                SshEnums.MessageType.SSH_MSG_CHANNEL_DATA -> {
                    val channelData = decryptedPacket.payload().body() as SshMsgChannelData
                    println("  Channel ${channelData.recipientChannel()}: ${String(channelData.data().data())}")
                }

                else -> {}
            }

            seqNum++
        }

        println("\nParsed $encryptedPacketCount encrypted packets")
        assertTrue(encryptedPacketCount > 0)
    }

    private fun parseKexMethodSpecific(packet: UnencryptedPacket.UnencryptedPayload) {
        val rawPayload = packet._raw_body()
        val messageTypeByte = packet.messageType().id().toByte()
        val fullPayload = byteArrayOf(messageTypeByte) + rawPayload

        val stream = ByteBufferKaitaiStream(fullPayload)
        val kexdhPayload = KexdhPayload(stream)
        kexdhPayload._read()

        println("  KEX method: ${kexdhPayload.messageType()}")

        when (kexdhPayload.messageType()) {
            SshEnums.KexDh.SSH_MSG_KEXDH_INIT -> {
                val init = kexdhPayload.body() as SshMsgKexdhInit
                println("  e: ${BigInteger(1, init.e().body()).toString(16).take(32)}...")
            }

            SshEnums.KexDh.SSH_MSG_KEXDH_REPLY -> {
                val reply = kexdhPayload.body() as SshMsgKexdhReply
                println("  f: ${BigInteger(1, reply.f().body()).toString(16).take(32)}...")
            }

            else -> {}
        }
    }

    private fun loadCaptureFile(name: String): ByteArray {
        val stream = javaClass.getResourceAsStream(name)
            ?: throw IllegalArgumentException("Capture file not found: $name")
        return stream.readBytes()
    }

    companion object {
        private const val AES_BLOCK_SIZE = 16
        private const val MAC_LENGTH = 32

        // Derived keys from the capture (server-to-client direction)
        // These would normally be computed from the key exchange, but for
        // testing with captured data we use the pre-computed values.

        // Key 'B' - Initial IV server-to-client
        private val INITIAL_IV_S_TO_C = byteArrayOf(
            0x4a.toByte(), 0xd0.toByte(), 0x83.toByte(), 0x35.toByte(),
            0x66.toByte(), 0xc6.toByte(), 0x2e.toByte(), 0xda.toByte(),
            0x2b.toByte(), 0xf4.toByte(), 0x5b.toByte(), 0x44.toByte(),
            0x79.toByte(), 0xda.toByte(), 0xcb.toByte(), 0xc2.toByte(),
        )

        // Key 'D' - Encryption key server-to-client
        private val CIPHER_KEY = byteArrayOf(
            0xf0.toByte(), 0x6f.toByte(), 0xc5.toByte(), 0x74.toByte(),
            0x24.toByte(), 0x38.toByte(), 0x6c.toByte(), 0x6c.toByte(),
            0x53.toByte(), 0x53.toByte(), 0xa0.toByte(), 0x2b.toByte(),
            0xa2.toByte(), 0xc0.toByte(), 0x45.toByte(), 0x82.toByte(),
        )

        // Key 'F' - MAC key server-to-client
        private val MAC_KEY = byteArrayOf(
            0xe0.toByte(), 0x03.toByte(), 0xa2.toByte(), 0x02.toByte(),
            0x7d.toByte(), 0x34.toByte(), 0x06.toByte(), 0xf0.toByte(),
            0x6c.toByte(), 0x9f.toByte(), 0xe4.toByte(), 0x45.toByte(),
            0x3d.toByte(), 0xf0.toByte(), 0xe1.toByte(), 0xe0.toByte(),
            0xb6.toByte(), 0xfb.toByte(), 0x21.toByte(), 0x0d.toByte(),
            0x6d.toByte(), 0xa6.toByte(), 0xfc.toByte(), 0x5a.toByte(),
            0xe4.toByte(), 0x86.toByte(), 0x61.toByte(), 0xac.toByte(),
            0x00.toByte(), 0x33.toByte(), 0xc4.toByte(), 0xce.toByte(),
        )

        private fun computeHmacSha256(key: ByteArray, seqNum: Int, encryptedLength: Long, encryptedPayload: ByteArray): ByteArray {
            val etmMac = EtmMac()
            etmMac.setSequenceNumber(seqNum.toLong())
            etmMac.setLenEncryptedPacket(encryptedLength)
            etmMac.setEncryptedPacket(encryptedPayload)

            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(etmMac.toByteArray())
        }

        private fun decryptAesCtr(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            return cipher.doFinal(data)
        }

        private fun incrementIv(iv: ByteArray, numBlocks: Int) {
            var carry = numBlocks
            for (i in iv.size - 1 downTo 1) {
                val sum = (iv[i].toInt() and 0xFF) + carry
                iv[i] = sum.toByte()
                carry = sum shr 8
                if (carry == 0) break
            }
        }
    }
}
