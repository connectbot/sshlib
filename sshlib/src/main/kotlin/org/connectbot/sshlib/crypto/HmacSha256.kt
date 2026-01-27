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

import org.connectbot.sshlib.struct.EtmMac
import org.connectbot.sshlib.struct.toByteArray
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-SHA256 message authentication code for SSH packets.
 *
 * Implements hmac-sha2-256 as specified in RFC 6668.
 *
 * @param key MAC key (32 bytes)
 */
class HmacSha256(private val key: ByteArray) : PacketMac {
    override val macLength: Int = 32

    private val mac: Mac = Mac.getInstance("HmacSHA256")
    private val keySpec = SecretKeySpec(key, "HmacSHA256")

    init {
        require(key.size == 32) {
            "HMAC-SHA256 key must be 32 bytes, got ${key.size}"
        }
        mac.init(keySpec)
    }

    override fun compute(sequenceNumber: Long, packet: ByteArray): ByteArray {
        mac.reset()

        // MAC is computed over: sequence_number || packet_data
        // sequence_number is uint32
        val buffer = ByteBuffer.allocate(4)
        buffer.putInt(sequenceNumber.toInt())

        mac.update(buffer.array())
        mac.update(packet)

        return mac.doFinal()
    }

    override fun computeEtm(sequenceNumber: Long, packetLength: Int, encryptedPayload: ByteArray): ByteArray {
        mac.reset()

        val etmMac = EtmMac()
        etmMac.setSequenceNumber(sequenceNumber)
        etmMac.setLenEncryptedPacket(packetLength.toLong())
        etmMac.setEncryptedPacket(encryptedPayload)

        mac.update(etmMac.toByteArray())
        return mac.doFinal()
    }
}
