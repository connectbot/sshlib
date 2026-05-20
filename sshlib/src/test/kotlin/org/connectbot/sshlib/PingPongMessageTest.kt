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

package org.connectbot.sshlib

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.protocol.SshMsgPing
import org.connectbot.sshlib.protocol.SshMsgPong
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class PingPongMessageTest {

    private fun buildPing(data: ByteArray): ByteArray {
        val msg = SshMsgPing()
        msg.setData(createByteString(data))
        msg._check()
        return msg.toByteArray()
    }

    private fun parsePing(bytes: ByteArray): SshMsgPing {
        val msg = SshMsgPing(ByteBufferKaitaiStream(bytes))
        msg._read()
        return msg
    }

    private fun buildPong(data: ByteArray): ByteArray {
        val msg = SshMsgPong()
        msg.setData(createByteString(data))
        msg._check()
        return msg.toByteArray()
    }

    private fun parsePong(bytes: ByteArray): SshMsgPong {
        val msg = SshMsgPong(ByteBufferKaitaiStream(bytes))
        msg._read()
        return msg
    }

    @Test
    fun `ping round-trip with empty data`() {
        val bytes = buildPing(byteArrayOf())
        val parsed = parsePing(bytes)
        assertArrayEquals(byteArrayOf(), parsed.data().data())
    }

    @Test
    fun `ping round-trip with non-empty data`() {
        val data = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
        val bytes = buildPing(data)
        val parsed = parsePing(bytes)
        assertArrayEquals(data, parsed.data().data())
    }

    @Test
    fun `pong round-trip preserves data exactly`() {
        val data = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A)
        val bytes = buildPong(data)
        val parsed = parsePong(bytes)
        assertArrayEquals(data, parsed.data().data())
    }

    @Test
    fun `pong with empty data round-trips`() {
        val bytes = buildPong(byteArrayOf())
        val parsed = parsePong(bytes)
        assertArrayEquals(byteArrayOf(), parsed.data().data())
    }
}
