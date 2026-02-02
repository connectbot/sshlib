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

package org.connectbot.sshlib.transport

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.crypto.PacketAead
import org.connectbot.sshlib.crypto.PacketCipher
import org.connectbot.sshlib.crypto.PacketMac
import org.connectbot.sshlib.struct.*
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.random.Random

/**
 * Handles SSH packet framing and unframing according to RFC 4253.
 *
 * SSH packets have the following structure:
 * ```
 * uint32    packet_length  // excludes MAC and itself
 * byte      padding_length
 * byte[n1]  payload        // n1 = packet_length - padding_length - 1
 * byte[n2]  padding        // n2 = padding_length
 * byte[m]   mac            // m = mac_length
 * ```
 *
 * @param transport Underlying transport layer
 */
class PacketIO(private val transport: Transport) {
    companion object {
        private val logger = LoggerFactory.getLogger(PacketIO::class.java)

        // Minimum packet_length: padding_length(1) + message_type(1) + min_padding(4) = 6
        private const val MIN_PACKET_LENGTH = 6
        private const val MAX_PACKET_LENGTH = 35000
    }

    // Separate ciphers and MACs for each direction
    private var sendCipher: PacketCipher? = null
    private var sendMac: PacketMac? = null
    private var receiveCipher: PacketCipher? = null
    private var receiveMac: PacketMac? = null

    // AEAD ciphers for each direction
    private var sendAead: PacketAead? = null
    private var receiveAead: PacketAead? = null

    // Whether to use ETM (Encrypt-then-MAC) mode for each direction
    private var sendEtm: Boolean = false
    private var receiveEtm: Boolean = false

    // Separate sequence numbers for each direction (client->server and server->client)
    private var sendSequenceNumber: Long = 0
    private var receiveSequenceNumber: Long = 0

    /**
     * Enable encryption and MAC for subsequent packets.
     *
     * @param clientToServerCipher Cipher for outgoing packets
     * @param clientToServerMac MAC for outgoing packets
     * @param serverToClientCipher Cipher for incoming packets
     * @param serverToClientMac MAC for incoming packets
     * @param clientToServerEtm Whether to use ETM for outgoing packets
     * @param serverToClientEtm Whether to use ETM for incoming packets
     */
    fun enableEncryption(
        clientToServerCipher: PacketCipher,
        clientToServerMac: PacketMac,
        serverToClientCipher: PacketCipher,
        serverToClientMac: PacketMac,
        clientToServerEtm: Boolean = false,
        serverToClientEtm: Boolean = false
    ) {
        this.sendCipher = clientToServerCipher
        this.sendMac = clientToServerMac
        this.receiveCipher = serverToClientCipher
        this.receiveMac = serverToClientMac
        this.sendEtm = clientToServerEtm
        this.receiveEtm = serverToClientEtm
    }

    /**
     * Enable AEAD encryption for subsequent packets.
     *
     * @param clientToServerAead AEAD cipher for outgoing packets
     * @param serverToClientAead AEAD cipher for incoming packets
     */
    fun enableAead(
        clientToServerAead: PacketAead,
        serverToClientAead: PacketAead
    ) {
        this.sendAead = clientToServerAead
        this.receiveAead = serverToClientAead
    }

    /**
     * Reset send sequence numbers to 0.
     * Required by strict KEX after NEWKEYS exchange (draft-ietf-sshm-strict-kex-01).
     */
    fun resetSendSequenceNumber() {
        sendSequenceNumber = 0
    }

    /**
     * Reset receive sequence number to 0.
     * Required by strict KEX after NEWKEYS exchange (draft-ietf-sshm-strict-kex-01).
     */
    fun resetReceiveSequenceNumber() {
        receiveSequenceNumber = 0
    }

    /**
     * Read and parse the next SSH packet.
     *
     * @return Parsed SSH message payload
     * @throws TransportException if packet is malformed or transport fails
     */
    suspend fun readPacket(): UnencryptedPacket.UnencryptedPayload {
        val currentAead = receiveAead
        if (currentAead != null) {
            return readAeadPacket(currentAead)
        }

        val currentCipher = receiveCipher
        val currentMac = receiveMac

        if (currentCipher == null || currentMac == null) {
            return readUnencryptedPacket()
        } else if (receiveEtm) {
            return readEtmPacket(currentCipher, currentMac)
        } else {
            return readEncryptedPacket(currentCipher, currentMac)
        }
    }

    private suspend fun readUnencryptedPacket(): UnencryptedPacket.UnencryptedPayload {
        // Read packet_length (4 bytes)
        val lengthBytes = transport.read(4)
        val packetLength = ByteBuffer.wrap(lengthBytes).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid packet length: $packetLength")
        }

        // Read rest of packet
        val packetData = transport.read(packetLength)

        // Combine length + data for Kaitai parsing
        val fullPacket = lengthBytes + packetData
        val stream = ByteBufferKaitaiStream(fullPacket)

        // Parse using Kaitai struct
        val packet = UnencryptedPacket(stream)
        packet._read()

        receiveSequenceNumber++
        return packet.payload()
    }

    private suspend fun readEncryptedPacket(cipher: PacketCipher, mac: PacketMac): UnencryptedPacket.UnencryptedPayload {
        val blockSize = cipher.blockSize
        val macLength = mac.macLength

        // Read first block (contains packet_length)
        val firstBlock = transport.read(blockSize)
        val decryptedFirst = cipher.decrypt(firstBlock)

        // Extract packet_length
        val packetLength = ByteBuffer.wrap(decryptedFirst, 0, 4).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid encrypted packet length: $packetLength")
        }

        // Read remaining encrypted data
        val remainingLength = packetLength - blockSize + 4
        val remainingData = if (remainingLength.compareTo(0) > 0) {
            transport.read(remainingLength)
        } else {
            byteArrayOf()
        }

        // Read MAC
        val receivedMac = transport.read(macLength)

        // Decrypt remaining data
        val decryptedRemaining = if (remainingData.isNotEmpty()) {
            cipher.decrypt(remainingData)
        } else {
            byteArrayOf()
        }

        // Combine decrypted blocks
        val decryptedPacket = decryptedFirst + decryptedRemaining

        // Verify MAC (over plaintext for encrypt-and-MAC)
        val expectedMac = mac.compute(receiveSequenceNumber, decryptedPacket)
        if (!receivedMac.contentEquals(expectedMac)) {
            logger.error("MAC verification failed for seq=$receiveSequenceNumber")
            logger.error("  Received MAC: ${receivedMac.joinToString("") { "%02x".format(it) }}")
            logger.error("  Expected MAC: ${expectedMac.joinToString("") { "%02x".format(it) }}")
            logger.error("  Decrypted packet (${decryptedPacket.size} bytes): ${decryptedPacket.joinToString("") { "%02x".format(it) }}")
            throw TransportException("MAC verification failed")
        }

        // Parse payload
        val stream = ByteBufferKaitaiStream(decryptedPacket)
        val packet = UnencryptedPacket(stream)
        packet._read()

        receiveSequenceNumber++
        return packet.payload()
    }

    /**
     * Read an ETM (Encrypt-then-MAC) packet.
     *
     * In ETM mode, the MAC is computed over (sequence_number || encrypted_length || encrypted_payload).
     * The length field is NOT encrypted.
     */
    private suspend fun readEtmPacket(cipher: PacketCipher, mac: PacketMac): UnencryptedPacket.UnencryptedPayload {
        val macLength = mac.macLength

        // In ETM mode, length is NOT encrypted
        val lengthBytes = transport.read(4)
        val encryptedLength = ByteBuffer.wrap(lengthBytes).int

        if (encryptedLength < MIN_PACKET_LENGTH || encryptedLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid ETM packet length: $encryptedLength")
        }

        // Read encrypted payload
        val encryptedPayload = transport.read(encryptedLength)

        // Read MAC
        val receivedMac = transport.read(macLength)

        // Verify MAC (over sequence_number || length || encrypted_payload)
        val expectedMac = mac.computeEtm(receiveSequenceNumber, encryptedLength, encryptedPayload)
        if (!receivedMac.contentEquals(expectedMac)) {
            logger.error("ETM MAC verification failed for seq=$receiveSequenceNumber")
            throw TransportException("ETM MAC verification failed")
        }

        // Decrypt
        val decryptedPayload = cipher.decrypt(encryptedPayload)

        // Rebuild full packet structure (length + decrypted payload) for parsing
        val fullPacket = lengthBytes + decryptedPayload
        val stream = ByteBufferKaitaiStream(fullPacket)
        val packet = UnencryptedPacket(stream)
        packet._read()

        receiveSequenceNumber++
        return packet.payload()
    }

    /**
     * Read an AEAD packet (e.g., AES-GCM per RFC 5647).
     *
     * Wire format: packet_length (4B, cleartext) || ciphertext || auth_tag (16B)
     * AAD: the 4-byte packet_length
     * Plaintext: padding_length || payload || padding
     */
    private suspend fun readAeadPacket(aead: PacketAead): UnencryptedPacket.UnencryptedPayload {
        val lengthBytes = transport.read(4)
        val packetLength = ByteBuffer.wrap(lengthBytes).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid AEAD packet length: $packetLength")
        }

        val ciphertext = transport.read(packetLength)
        val tag = transport.read(aead.tagLength)

        val plaintext = aead.decrypt(lengthBytes, ciphertext, tag)

        val fullPacket = lengthBytes + plaintext
        val stream = ByteBufferKaitaiStream(fullPacket)
        val packet = UnencryptedPacket(stream)
        packet._read()

        receiveSequenceNumber++
        return packet.payload()
    }

    /**
     * Write an SSH packet.
     *
     * @param messageType SSH message type code
     * @param payload Message payload (excluding message type byte)
     */
    suspend fun writePacket(messageType: Int, payload: ByteArray = byteArrayOf()) {
        val currentAead = sendAead
        if (currentAead != null) {
            writeAeadPacket(messageType, payload, currentAead)
            return
        }

        val currentCipher = sendCipher
        val currentMac = sendMac

        if (currentCipher == null || currentMac == null) {
            writeUnencryptedPacket(messageType, payload)
        } else if (sendEtm) {
            writeEtmPacket(messageType, payload, currentCipher, currentMac)
        } else {
            writeEncryptedPacket(messageType, payload, currentCipher, currentMac)
        }
    }

    private suspend fun writeUnencryptedPacket(messageType: Int, payload: ByteArray) {
        val payloadLength = 1 + payload.size // message type + payload
        val blockSize = 8 // Minimum block size per RFC 4253

        // Calculate padding
        val paddingLength = calculatePaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // Build packet
        val buffer = ByteArrayOutputStream()

        // packet_length (4 bytes)
        buffer.write(ByteBuffer.allocate(4).putInt(packetLength).array())

        // padding_length (1 byte)
        buffer.write(paddingLength)

        // message type (1 byte)
        buffer.write(messageType)

        // payload
        buffer.write(payload)

        // padding (random bytes)
        val padding = Random.nextBytes(paddingLength)
        buffer.write(padding)

        transport.write(buffer.toByteArray())
        sendSequenceNumber++
    }

    private suspend fun writeEncryptedPacket(
        messageType: Int,
        payload: ByteArray,
        cipher: PacketCipher,
        mac: PacketMac
    ) {
        val payloadLength = 1 + payload.size
        val blockSize = cipher.blockSize

        // Calculate padding
        val paddingLength = calculatePaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // Build unencrypted packet
        val buffer = ByteArrayOutputStream()

        // packet_length (4 bytes)
        buffer.write(ByteBuffer.allocate(4).putInt(packetLength).array())

        // padding_length (1 byte)
        buffer.write(paddingLength)

        // message type (1 byte)
        buffer.write(messageType)

        // payload
        buffer.write(payload)

        // padding (random bytes)
        val padding = Random.nextBytes(paddingLength)
        buffer.write(padding)

        val unencryptedPacket = buffer.toByteArray()

        // Compute MAC before encryption (over plaintext)
        val macBytes = mac.compute(sendSequenceNumber, unencryptedPacket)

        // Encrypt packet
        val encryptedPacket = cipher.encrypt(unencryptedPacket)

        // Send encrypted packet + MAC
        transport.write(encryptedPacket + macBytes)
        sendSequenceNumber++
    }

    /**
     * Write an ETM (Encrypt-then-MAC) packet.
     *
     * In ETM mode, the length field is NOT encrypted, and MAC is computed over
     * (sequence_number || packet_length || encrypted_payload).
     */
    private suspend fun writeEtmPacket(
        messageType: Int,
        payload: ByteArray,
        cipher: PacketCipher,
        mac: PacketMac
    ) {
        val payloadLength = 1 + payload.size
        val blockSize = cipher.blockSize

        // Calculate padding (length field is not encrypted in ETM)
        val paddingLength = calculateAeadPaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // Build the payload to encrypt (padding_length + message type + payload + padding)
        val payloadBuffer = ByteArrayOutputStream()
        payloadBuffer.write(paddingLength)
        payloadBuffer.write(messageType)
        payloadBuffer.write(payload)
        val padding = Random.nextBytes(paddingLength)
        payloadBuffer.write(padding)

        val payloadToEncrypt = payloadBuffer.toByteArray()

        // Encrypt payload (NOT including length)
        val encryptedPayload = cipher.encrypt(payloadToEncrypt)

        // Compute MAC over sequence_number || packet_length || encrypted_payload
        val macBytes = mac.computeEtm(sendSequenceNumber, packetLength, encryptedPayload)

        // Build final packet: length (unencrypted) + encrypted_payload + MAC
        val lengthBytes = ByteBuffer.allocate(4).putInt(packetLength).array()
        transport.write(lengthBytes + encryptedPayload + macBytes)
        sendSequenceNumber++
    }

    /**
     * Write an AEAD packet (e.g., AES-GCM per RFC 5647).
     *
     * Wire format: packet_length (4B, cleartext) || ciphertext || auth_tag (16B)
     * Plaintext: padding_length || message_type || payload || padding
     * Padding must align the plaintext to a 16-byte boundary.
     */
    private suspend fun writeAeadPacket(
        messageType: Int,
        payload: ByteArray,
        aead: PacketAead
    ) {
        val payloadLength = 1 + payload.size // message type + payload
        val blockSize = 16 // AES block size for GCM padding alignment

        val paddingLength = calculateAeadPaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        val plaintextBuffer = ByteArrayOutputStream()
        plaintextBuffer.write(paddingLength)
        plaintextBuffer.write(messageType)
        plaintextBuffer.write(payload)
        plaintextBuffer.write(Random.nextBytes(paddingLength))

        val plaintext = plaintextBuffer.toByteArray()
        val lengthBytes = ByteBuffer.allocate(4).putInt(packetLength).array()

        val result = aead.encrypt(lengthBytes, plaintext)

        transport.write(lengthBytes + result.ciphertext + result.tag)
        sendSequenceNumber++
    }

    /**
     * Calculate padding length according to RFC 4253 section 6.
     *
     * The padding length must be such that:
     * - Total length (packet_length + 4 bytes) is a multiple of block size (or 8)
     * - Padding is at least 4 bytes
     * - Padding is less than 256 bytes
     */
    private fun calculatePaddingLength(payloadLength: Int, blockSize: Int): Int {
        val minBlockSize = maxOf(8, blockSize)
        val totalLength = 4 + 1 + payloadLength // length field + padding_length + payload

        // Find padding that makes total length a multiple of block size
        var paddingLength = minBlockSize - (totalLength % minBlockSize)

        // Ensure minimum padding of 4 bytes
        if (paddingLength < 4) {
            paddingLength += minBlockSize
        }

        return paddingLength
    }

    /**
     * Calculate padding length for ETM/AEAD packets.
     *
     * For ETM and AEAD, the 4-byte length field is not encrypted, so alignment
     * is on the encrypted portion (padding_length + payload + padding) only.
     */
    private fun calculateAeadPaddingLength(payloadLength: Int, blockSize: Int): Int {
        val contentLength = 1 + payloadLength // padding_length byte + payload
        val slack = contentLength % blockSize
        var paddingLength = if (slack == 0) 0 else blockSize - slack

        if (paddingLength < 4) {
            paddingLength += blockSize
        }

        return paddingLength
    }

    /**
     * Read the SSH version banner (plain text before packet protocol).
     *
     * @return Parsed banner
     */
    suspend fun readBanner(): IdBanner {
        val bannerBytes = ByteArrayOutputStream()

        // Read until we get \r\n (RFC 4253 section 4.2)
        while (true) {
            val byte = transport.read(1)[0]
            bannerBytes.write(byte.toInt())

            if (bannerBytes.size() >= 2) {
                val bytes = bannerBytes.toByteArray()
                if (bytes[bytes.size - 2] == '\r'.code.toByte() &&
                    bytes[bytes.size - 1] == '\n'.code.toByte()) {
                    break
                }
            }

            // Prevent infinite loop on malformed banner
            if (bannerBytes.size() > 255) {
                throw TransportException("Banner too long")
            }
        }

        val stream = ByteBufferKaitaiStream(bannerBytes.toByteArray())
        val banner = IdBanner(stream)
        banner._read()
        return banner
    }

    /**
     * Write the SSH version banner.
     *
     * @param version Version string (e.g., "SSH-2.0-MyClient_1.0")
     */
    suspend fun writeBanner(version: String) {
        val banner = "$version\r\n"
        transport.write(banner.toByteArray(Charsets.US_ASCII))
    }
}
