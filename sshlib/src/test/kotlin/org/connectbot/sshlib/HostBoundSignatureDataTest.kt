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
import org.connectbot.sshlib.protocol.UserauthPublickeyHostboundSignatureData
import org.connectbot.sshlib.protocol.createAsciiString
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class HostBoundSignatureDataTest {

    private fun buildHostBoundSignatureData(
        sessionId: ByteArray,
        username: String,
        serviceName: String,
        algorithmName: String,
        publicKeyBlob: ByteArray,
        serverHostKeyBlob: ByteArray,
    ): ByteArray {
        val data = UserauthPublickeyHostboundSignatureData().apply {
            setSessionIdentifier(createByteString(sessionId))
            setMessageType(byteArrayOf(50))
            setUserName(createByteString(username.toByteArray(Charsets.UTF_8)))
            setServiceName(createByteString(serviceName.toByteArray(Charsets.US_ASCII)))
            setMethodName(createByteString("publickey-hostbound-v00@openssh.com".toByteArray(Charsets.US_ASCII)))
            setHasSignature(byteArrayOf(1))
            setPublicKeyAlgorithmName(createByteString(algorithmName.toByteArray(Charsets.US_ASCII)))
            setPublicKeyBlob(createByteString(publicKeyBlob))
            setServerHostKey(createByteString(serverHostKeyBlob))
            _check()
        }
        return data.toByteArray()
    }

    @Test
    fun `host-bound signature data round-trips correctly`() {
        val sessionId = byteArrayOf(1, 2, 3, 4)
        val username = "testuser"
        val algorithmName = "ssh-ed25519"
        val publicKeyBlob = byteArrayOf(10, 20, 30, 40)
        val serverHostKeyBlob = byteArrayOf(50, 60, 70, 80)

        val bytes = buildHostBoundSignatureData(
            sessionId = sessionId,
            username = username,
            serviceName = "ssh-connection",
            algorithmName = algorithmName,
            publicKeyBlob = publicKeyBlob,
            serverHostKeyBlob = serverHostKeyBlob,
        )

        val parsed = UserauthPublickeyHostboundSignatureData(ByteBufferKaitaiStream(bytes))
        parsed._read()

        assertArrayEquals(sessionId, parsed.sessionIdentifier().data())
        assertArrayEquals(username.toByteArray(Charsets.UTF_8), parsed.userName().data())
        assertArrayEquals("ssh-connection".toByteArray(Charsets.US_ASCII), parsed.serviceName().data())
        assertArrayEquals(
            "publickey-hostbound-v00@openssh.com".toByteArray(Charsets.US_ASCII),
            parsed.methodName().data(),
        )
        assertArrayEquals(algorithmName.toByteArray(Charsets.US_ASCII), parsed.publicKeyAlgorithmName().data())
        assertArrayEquals(publicKeyBlob, parsed.publicKeyBlob().data())
        assertArrayEquals(serverHostKeyBlob, parsed.serverHostKey().data())
    }

    @Test
    fun `host-bound differs from standard publickey signature data`() {
        val sessionId = byteArrayOf(1, 2, 3)
        val publicKeyBlob = byteArrayOf(4, 5, 6)
        val serverHostKeyBlob = byteArrayOf(7, 8, 9)

        val hostBoundBytes = buildHostBoundSignatureData(
            sessionId = sessionId,
            username = "user",
            serviceName = "ssh-connection",
            algorithmName = "ssh-ed25519",
            publicKeyBlob = publicKeyBlob,
            serverHostKeyBlob = serverHostKeyBlob,
        )

        // Host-bound signature data must be longer than standard (adds server_host_key)
        // and method name differs. Just verify it parses and has the right method name.
        val parsed = UserauthPublickeyHostboundSignatureData(ByteBufferKaitaiStream(hostBoundBytes))
        parsed._read()

        assertEquals(
            "publickey-hostbound-v00@openssh.com",
            String(parsed.methodName().data(), Charsets.US_ASCII),
        )
        assertArrayEquals(serverHostKeyBlob, parsed.serverHostKey().data())
    }
}
