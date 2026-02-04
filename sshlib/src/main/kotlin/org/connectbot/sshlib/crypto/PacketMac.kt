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

package org.connectbot.sshlib.crypto

/**
 * Interface for SSH packet message authentication codes (MAC).
 */
internal interface PacketMac {
    /**
     * MAC length in bytes.
     */
    val macLength: Int

    /**
     * Compute MAC for packet (encrypt-and-MAC mode).
     *
     * @param sequenceNumber Packet sequence number
     * @param packet Complete packet data (including length, padding, etc.)
     * @return MAC bytes
     */
    fun compute(sequenceNumber: Long, packet: ByteArray): ByteArray

    /**
     * Compute MAC for ETM (Encrypt-then-MAC) mode.
     *
     * In ETM mode, the MAC is computed over: sequence_number || packet_length || encrypted_payload
     * where packet_length is the unencrypted 4-byte length field.
     *
     * @param sequenceNumber Packet sequence number
     * @param packetLength The packet length (from unencrypted length field)
     * @param encryptedPayload The encrypted payload (excluding length field)
     * @return MAC bytes
     */
    fun computeEtm(sequenceNumber: Long, packetLength: Int, encryptedPayload: ByteArray): ByteArray
}
