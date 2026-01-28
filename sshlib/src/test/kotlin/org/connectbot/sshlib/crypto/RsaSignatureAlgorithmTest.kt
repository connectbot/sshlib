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
import org.connectbot.sshlib.struct.SshPublicKey
import org.connectbot.sshlib.struct.SshSignature
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RsaSignatureAlgorithmTest {

    private fun encodeString(out: DataOutputStream, value: ByteArray) {
        out.writeInt(value.size)
        out.write(value)
    }

    private fun encodeString(out: DataOutputStream, value: String) {
        encodeString(out, value.toByteArray(Charsets.US_ASCII))
    }

    private fun encodeMpint(out: DataOutputStream, value: java.math.BigInteger) {
        val bytes = value.toByteArray()
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun buildRsaHostKey(pub: RSAPublicKey): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, "ssh-rsa")
        encodeMpint(out, pub.publicExponent)
        encodeMpint(out, pub.modulus)
        return buf.toByteArray()
    }

    private fun buildRsaSignature(algorithmName: String, signatureBytes: ByteArray): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, algorithmName)
        encodeString(out, signatureBytes)
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
    fun `verifies valid rsa-sha2-256 signature`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val pub = kp.public as RSAPublicKey
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(kp.private)
        sig.update(data)
        val sigBytes = sig.sign()

        val hostKey = buildRsaHostKey(pub)
        val sshSig = buildRsaSignature("rsa-sha2-256", sigBytes)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertTrue(RsaSignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }

    @Test
    fun `verifies valid rsa-sha2-512 signature`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val pub = kp.public as RSAPublicKey
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("SHA512withRSA")
        sig.initSign(kp.private)
        sig.update(data)
        val sigBytes = sig.sign()

        val hostKey = buildRsaHostKey(pub)
        val sshSig = buildRsaSignature("rsa-sha2-512", sigBytes)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertTrue(RsaSignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }

    @Test
    fun `rejects invalid rsa signature`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val pub = kp.public as RSAPublicKey
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(kp.private)
        sig.update("wrong data".toByteArray())
        val sigBytes = sig.sign()

        val hostKey = buildRsaHostKey(pub)
        val sshSig = buildRsaSignature("rsa-sha2-256", sigBytes)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertFalse(RsaSignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }
}
