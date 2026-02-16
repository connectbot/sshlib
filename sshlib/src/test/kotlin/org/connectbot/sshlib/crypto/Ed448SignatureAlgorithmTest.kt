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

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Ed448SignatureAlgorithmTest {

    private fun encodeString(out: DataOutputStream, value: ByteArray) {
        out.writeInt(value.size)
        out.write(value)
    }

    private fun encodeString(out: DataOutputStream, value: String) {
        encodeString(out, value.toByteArray(Charsets.US_ASCII))
    }

    private fun buildEd448HostKey(rawKey: ByteArray): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, "ssh-ed448")
        encodeString(out, rawKey)
        return buf.toByteArray()
    }

    private fun buildEd448Signature(sigBytes: ByteArray): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, "ssh-ed448")
        encodeString(out, sigBytes)
        return buf.toByteArray()
    }

    private fun parse(hostKey: ByteArray, sshSig: ByteArray): Pair<SshPublicKey, SshSignature> {
        val pubKey = SshPublicKey(ByteBufferKaitaiStream(hostKey))
        pubKey._read()
        val sig = SshSignature(ByteBufferKaitaiStream(sshSig))
        sig._read()
        return pubKey to sig
    }

    @Test
    fun `verifies valid ed448 signature`() {
        val kp = KeyPairGenerator.getInstance("Ed448").generateKeyPair()
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("Ed448")
        sig.initSign(kp.private)
        sig.update(data)
        val sigBytes = sig.sign()

        val rawKey = kp.public.encoded.let { it.copyOfRange(it.size - 57, it.size) }
        val hostKey = buildEd448HostKey(rawKey)
        val sshSig = buildEd448Signature(sigBytes)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertTrue(Ed448SignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }

    @Test
    fun `rejects invalid ed448 signature`() {
        val kp = KeyPairGenerator.getInstance("Ed448").generateKeyPair()
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("Ed448")
        sig.initSign(kp.private)
        sig.update("wrong data".toByteArray())
        val sigBytes = sig.sign()

        val rawKey = kp.public.encoded.let { it.copyOfRange(it.size - 57, it.size) }
        val hostKey = buildEd448HostKey(rawKey)
        val sshSig = buildEd448Signature(sigBytes)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertFalse(Ed448SignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }
}
