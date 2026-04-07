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
import org.connectbot.sshlib.crypto.PacketCompressor
import org.connectbot.sshlib.crypto.PacketMac
import org.connectbot.sshlib.protocol.IdBanner
import org.connectbot.sshlib.protocol.UnencryptedPacket
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
internal class PacketIO(private val transport: Transport) {
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

    // Compression state
    private var sendCompressor: PacketCompressor? = null
    private var receiveCompressor: PacketCompressor? = null
    private var sendCompressionActive: Boolean = false
    private var receiveCompressionActive: Boolean = false

    // Wire-byte counters for re-key threshold tracking
    internal var bytesSentOnWire: Long = 0L
    internal var bytesReceivedOnWire: Long = 0L

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
        serverToClientEtm: Boolean = false,
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
        serverToClientAead: PacketAead,
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
     * Install compressors for both directions.
     *
     * @param clientToServer Compressor for outgoing packets (null for "none")
     * @param serverToClient Compressor for incoming packets (null for "none")
     * @param immediateActivation If true, compression starts immediately; if false,
     *   compressors are installed but inactive until [activateCompression] is called.
     */
    fun enableCompression(
        clientToServer: PacketCompressor?,
        serverToClient: PacketCompressor?,
        immediateActivation: Boolean,
    ) {
        this.sendCompressor = clientToServer
        this.receiveCompressor = serverToClient
        if (immediateActivation) {
            this.sendCompressionActive = clientToServer != null
            this.receiveCompressionActive = serverToClient != null
        }
    }

    /**
     * Activate installed-but-inactive compressors.
     * Used for `zlib@openssh.com` which delays compression until after user authentication.
     */
    fun activateCompression() {
        if (sendCompressor != null) sendCompressionActive = true
        if (receiveCompressor != null) receiveCompressionActive = true
    }

    fun resetByteCounters() {
        bytesSentOnWire = 0L
        bytesReceivedOnWire = 0L
    }

    /**
     * Read and parse the next SSH packet, decompressing if compression is active.
     *
     * @return Parsed SSH message payload
     * @throws TransportException if packet is malformed or transport fails
     */
    suspend fun readPacket(): UnencryptedPacket.UnencryptedPayload {
        val rawPayloadBytes = readRawPayloadBytes()

        val compressor = receiveCompressor
        val payloadBytes = if (compressor != null && receiveCompressionActive) {
            compressor.uncompress(rawPayloadBytes)
        } else {
            rawPayloadBytes
        }

        return parsePayloadBytes(payloadBytes)
    }

    /**
     * Wrap raw payload bytes in a minimal UnencryptedPacket frame so Kaitai
     * can parse them with proper parent context for body length calculation.
     */
    private fun parsePayloadBytes(payloadBytes: ByteArray): UnencryptedPacket.UnencryptedPayload {
        val paddingLength = 4
        val packetLength = 1 + payloadBytes.size + paddingLength
        val buffer = ByteArrayOutputStream()
        buffer.write(ByteBuffer.allocate(4).putInt(packetLength).array())
        buffer.write(paddingLength)
        buffer.write(payloadBytes)
        buffer.write(ByteArray(paddingLength))
        val fullPacket = buffer.toByteArray()
        val stream = ByteBufferKaitaiStream(fullPacket)
        val packet = UnencryptedPacket(stream)
        packet._read()
        return packet.payload()
    }

    /**
     * Read and decrypt/verify the next SSH packet, returning the raw payload bytes
     * (message_type + body) before decompression.
     */
    private suspend fun readRawPayloadBytes(): ByteArray {
        val currentAead = receiveAead
        if (currentAead != null) {
            return readAeadPacketBytes(currentAead)
        }

        val currentCipher = receiveCipher
        val currentMac = receiveMac

        if (currentCipher == null || currentMac == null) {
            return readUnencryptedPacketBytes()
        } else if (receiveEtm) {
            return readEtmPacketBytes(currentCipher, currentMac)
        } else {
            return readEncryptedPacketBytes(currentCipher, currentMac)
        }
    }

    /**
     * Extract the payload bytes (message_type + body) from a decrypted packet.
     * The decrypted packet is: packet_length(4) + padding_length(1) + payload + padding.
     */
    private fun extractPayloadBytes(decryptedPacket: ByteArray): ByteArray {
        val paddingLength = decryptedPacket[4].toInt() and 0xFF
        val packetLength = ByteBuffer.wrap(decryptedPacket, 0, 4).int
        val payloadLength = packetLength - paddingLength - 1
        return decryptedPacket.copyOfRange(5, 5 + payloadLength)
    }

    private suspend fun readUnencryptedPacketBytes(): ByteArray {
        // Read packet_length (4 bytes)
        val lengthBytes = transport.read(4)
        bytesReceivedOnWire += 4
        val packetLength = ByteBuffer.wrap(lengthBytes).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid packet length: $packetLength")
        }

        // Read rest of packet
        val packetData = transport.read(packetLength)
        bytesReceivedOnWire += packetLength

        receiveSequenceNumber++
        val fullPacket = lengthBytes + packetData
        return extractPayloadBytes(fullPacket)
    }

    private suspend fun readEncryptedPacketBytes(cipher: PacketCipher, mac: PacketMac): ByteArray {
        val blockSize = cipher.blockSize
        val macLength = mac.macLength

        // Read first block (contains packet_length)
        val firstBlock = transport.read(blockSize)
        bytesReceivedOnWire += blockSize
        val decryptedFirst = cipher.decrypt(firstBlock)

        // Extract packet_length
        val packetLength = ByteBuffer.wrap(decryptedFirst, 0, 4).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid encrypted packet length: $packetLength")
        }

        // Read remaining encrypted data
        val remainingLength = packetLength - blockSize + 4
        val remainingData = if (remainingLength.compareTo(0) > 0) {
            transport.read(remainingLength).also { bytesReceivedOnWire += remainingLength }
        } else {
            byteArrayOf()
        }

        // Read MAC
        val receivedMac = transport.read(macLength)
        bytesReceivedOnWire += macLength

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

        receiveSequenceNumber++
        return extractPayloadBytes(decryptedPacket)
    }

    /**
     * Read an ETM (Encrypt-then-MAC) packet.
     *
     * In ETM mode, the MAC is computed over (sequence_number || encrypted_length || encrypted_payload).
     * The length field is NOT encrypted.
     */
    private suspend fun readEtmPacketBytes(cipher: PacketCipher, mac: PacketMac): ByteArray {
        val macLength = mac.macLength

        // In ETM mode, length is NOT encrypted
        val lengthBytes = transport.read(4)
        bytesReceivedOnWire += 4
        val encryptedLength = ByteBuffer.wrap(lengthBytes).int

        if (encryptedLength < MIN_PACKET_LENGTH || encryptedLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid ETM packet length: $encryptedLength")
        }

        // Read encrypted payload
        val encryptedPayload = transport.read(encryptedLength)
        bytesReceivedOnWire += encryptedLength

        // Read MAC
        val receivedMac = transport.read(macLength)
        bytesReceivedOnWire += macLength

        // Verify MAC (over sequence_number || length || encrypted_payload)
        val expectedMac = mac.computeEtm(receiveSequenceNumber, encryptedLength, encryptedPayload)
        if (!receivedMac.contentEquals(expectedMac)) {
            logger.error("ETM MAC verification failed for seq=$receiveSequenceNumber")
            throw TransportException("ETM MAC verification failed")
        }

        // Decrypt
        val decryptedPayload = cipher.decrypt(encryptedPayload)

        // Rebuild full packet structure for payload extraction
        val fullPacket = lengthBytes + decryptedPayload
        receiveSequenceNumber++
        return extractPayloadBytes(fullPacket)
    }

    /**
     * Read an AEAD packet (e.g., AES-GCM per RFC 5647).
     *
     * Wire format: packet_length (4B, cleartext) || ciphertext || auth_tag (16B)
     * AAD: the 4-byte packet_length
     * Plaintext: padding_length || payload || padding
     *
     * For ciphers that encrypt the length (e.g., ChaCha20-Poly1305):
     * Wire format: encrypted_length (4B) || ciphertext || auth_tag (16B)
     * The encrypted length bytes are passed as AAD to encrypt/decrypt.
     */
    private suspend fun readAeadPacketBytes(aead: PacketAead): ByteArray {
        val wireLength = transport.read(4)
        bytesReceivedOnWire += 4

        val lengthBytes: ByteArray
        val aadBytes: ByteArray
        if (aead.encryptsLength) {
            aadBytes = wireLength.clone()
            lengthBytes = aead.decryptLength(receiveSequenceNumber, wireLength)
        } else {
            lengthBytes = wireLength
            aadBytes = wireLength
        }

        val packetLength = ByteBuffer.wrap(lengthBytes).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid AEAD packet length: $packetLength")
        }

        val ciphertext = transport.read(packetLength)
        bytesReceivedOnWire += packetLength
        val tag = transport.read(aead.tagLength)
        bytesReceivedOnWire += aead.tagLength

        val plaintext = aead.decrypt(aadBytes, ciphertext, tag)

        val fullPacket = lengthBytes + plaintext
        receiveSequenceNumber++
        return extractPayloadBytes(fullPacket)
    }

    /**
     * Write an SSH packet, compressing if compression is active.
     *
     * @param messageType SSH message type code
     * @param payload Message payload (excluding message type byte)
     */
    suspend fun writePacket(messageType: Int, payload: ByteArray = byteArrayOf()) {
        val compressor = sendCompressor
        if (compressor != null && sendCompressionActive) {
            val uncompressed = byteArrayOf(messageType.toByte()) + payload
            val compressed = compressor.compress(uncompressed)
            writeRawPacket(compressed[0].toInt() and 0xFF, compressed.copyOfRange(1, compressed.size))
        } else {
            writeRawPacket(messageType, payload)
        }
    }

    private suspend fun writeRawPacket(messageType: Int, payload: ByteArray = byteArrayOf()) {
        logger.debug("Writing packet type $messageType (seq=$sendSequenceNumber)")
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

        val data = buffer.toByteArray()
        transport.write(data)
        bytesSentOnWire += data.size
        sendSequenceNumber++
    }

    private suspend fun writeEncryptedPacket(
        messageType: Int,
        payload: ByteArray,
        cipher: PacketCipher,
        mac: PacketMac,
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
        val data = encryptedPacket + macBytes
        transport.write(data)
        bytesSentOnWire += data.size
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
        mac: PacketMac,
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
        val data = lengthBytes + encryptedPayload + macBytes
        transport.write(data)
        bytesSentOnWire += data.size
        sendSequenceNumber++
    }

    /**
     * Write an AEAD packet (e.g., AES-GCM per RFC 5647).
     *
     * Wire format: packet_length (4B, cleartext) || ciphertext || auth_tag (16B)
     * Plaintext: padding_length || message_type || payload || padding
     * Padding must align the plaintext to a 16-byte boundary.
     *
     * For ciphers that encrypt the length (e.g., ChaCha20-Poly1305):
     * Wire format: encrypted_length (4B) || ciphertext || auth_tag (16B)
     * The encrypted length bytes are passed as AAD to encrypt.
     */
    private suspend fun writeAeadPacket(
        messageType: Int,
        payload: ByteArray,
        aead: PacketAead,
    ) {
        val payloadLength = 1 + payload.size // message type + payload
        val blockSize = if (aead.encryptsLength) 8 else 16

        val paddingLength = calculateAeadPaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        val plaintextBuffer = ByteArrayOutputStream()
        plaintextBuffer.write(paddingLength)
        plaintextBuffer.write(messageType)
        plaintextBuffer.write(payload)
        plaintextBuffer.write(Random.nextBytes(paddingLength))

        val plaintext = plaintextBuffer.toByteArray()
        val lengthBytes = ByteBuffer.allocate(4).putInt(packetLength).array()

        val wireLength: ByteArray
        val aadBytes: ByteArray
        if (aead.encryptsLength) {
            wireLength = aead.encryptLength(sendSequenceNumber, lengthBytes)
            aadBytes = wireLength
        } else {
            wireLength = lengthBytes
            aadBytes = lengthBytes
        }

        val result = aead.encrypt(aadBytes, plaintext)

        val data = wireLength + result.ciphertext + result.tag
        transport.write(data)
        bytesSentOnWire += data.size
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
                    bytes[bytes.size - 1] == '\n'.code.toByte()
                ) {
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
