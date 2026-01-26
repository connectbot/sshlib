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

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-SHA512 message authentication code for SSH packets.
 *
 * Implements hmac-sha2-512 as specified in RFC 6668.
 *
 * @param key MAC key (64 bytes)
 */
class HmacSha512(private val key: ByteArray) : PacketMac {
    override val macLength: Int = 64

    private val mac: Mac = Mac.getInstance("HmacSHA512")
    private val keySpec = SecretKeySpec(key, "HmacSHA512")

    init {
        require(key.size == 64) {
            "HMAC-SHA512 key must be 64 bytes, got ${key.size}"
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
}
