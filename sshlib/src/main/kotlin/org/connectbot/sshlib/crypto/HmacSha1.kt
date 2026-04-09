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

import org.connectbot.sshlib.protocol.EtmMac
import org.connectbot.sshlib.protocol.toByteArray
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-SHA-1 message authentication code for SSH packets.
 *
 * Implements hmac-sha1 as specified in RFC 4253.
 *
 * @param key MAC key (20 bytes)
 */
internal class HmacSha1(private val key: ByteArray) : PacketMac {
    override val macLength: Int = 20

    private val mac: Mac = Mac.getInstance("HmacSHA1")
    private val keySpec = SecretKeySpec(key, "HmacSHA1")

    init {
        require(key.size == 20) {
            "HMAC-SHA1 key must be 20 bytes, got ${key.size}"
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

    override fun destroy() {
        key.fill(0)
    }
}
