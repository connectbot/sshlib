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

package org.connectbot.sshlib

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.protocol.SshMsgExtInfo
import org.connectbot.sshlib.protocol.createAsciiString
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ExtInfoProcessingTest {

    private fun buildExtInfo(extensions: Map<String, ByteArray>): ByteArray {
        val msg = SshMsgExtInfo()
        msg.setNumExtensions(extensions.size.toLong())
        val extList = ArrayList<SshMsgExtInfo.Extension>()
        for ((name, value) in extensions) {
            val ext = SshMsgExtInfo.Extension()
            ext.set_root(msg)
            ext.set_parent(msg)
            ext.setExtensionName(createAsciiString(name))
            ext.setExtensionValue(createByteString(value))
            ext._check()
            extList.add(ext)
        }
        msg.setExtensions(extList)
        msg._check()
        return msg.toByteArray()
    }

    private fun detectsHostBound(bytes: ByteArray): Boolean {
        val parsed = SshMsgExtInfo(ByteBufferKaitaiStream(bytes))
        parsed._read()
        return parsed.extensions().any { it.extensionName().value() == "publickey-hostbound@openssh.com" }
    }

    @Test
    fun `detects publickey-hostbound extension`() {
        val bytes = buildExtInfo(
            mapOf("publickey-hostbound@openssh.com" to "0".toByteArray()),
        )
        assertTrue(detectsHostBound(bytes))
    }

    @Test
    fun `does not detect hostbound when extension absent`() {
        val bytes = buildExtInfo(
            mapOf("server-sig-algs" to "ssh-ed25519,ssh-rsa".toByteArray()),
        )
        assertFalse(detectsHostBound(bytes))
    }

    @Test
    fun `handles multiple extensions including hostbound`() {
        val bytes = buildExtInfo(
            mapOf(
                "server-sig-algs" to "ssh-ed25519".toByteArray(),
                "publickey-hostbound@openssh.com" to "0".toByteArray(),
                "no-flow-control" to byteArrayOf(),
            ),
        )
        assertTrue(detectsHostBound(bytes))
    }

    @Test
    fun `handles empty extension list`() {
        val bytes = buildExtInfo(emptyMap())
        assertFalse(detectsHostBound(bytes))
    }

    @Test
    fun `extension count is correct`() {
        val bytes = buildExtInfo(
            mapOf(
                "ext1" to "val1".toByteArray(),
                "ext2" to "val2".toByteArray(),
            ),
        )
        val parsed = SshMsgExtInfo(ByteBufferKaitaiStream(bytes))
        parsed._read()
        assertEquals(2, parsed.numExtensions().toInt())
        assertEquals(2, parsed.extensions().size)
    }
}
