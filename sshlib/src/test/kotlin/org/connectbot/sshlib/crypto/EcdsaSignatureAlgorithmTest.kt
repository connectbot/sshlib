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
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EcdsaSignatureAlgorithmTest {

    private fun encodeString(out: DataOutputStream, value: ByteArray) {
        out.writeInt(value.size)
        out.write(value)
    }

    private fun encodeString(out: DataOutputStream, value: String) {
        encodeString(out, value.toByteArray(Charsets.US_ASCII))
    }

    private fun encodeMpint(out: DataOutputStream, value: BigInteger) {
        val bytes = value.toByteArray()
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun buildEcdsaHostKey(pub: ECPublicKey, curveName: String): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        val identifier = "ecdsa-sha2-$curveName"
        encodeString(out, identifier)
        encodeString(out, curveName)
        val point = pub.w
        val fieldSize = (pub.params.order.bitLength() + 7) / 8
        val x = point.affineX.toByteArray().let { if (it.size > fieldSize) it.copyOfRange(it.size - fieldSize, it.size) else it }
        val y = point.affineY.toByteArray().let { if (it.size > fieldSize) it.copyOfRange(it.size - fieldSize, it.size) else it }
        val qBytes = ByteArray(1 + 2 * fieldSize)
        qBytes[0] = 0x04
        System.arraycopy(x, 0, qBytes, 1 + fieldSize - x.size, x.size)
        System.arraycopy(y, 0, qBytes, 1 + 2 * fieldSize - y.size, y.size)
        encodeString(out, qBytes)
        return buf.toByteArray()
    }

    private fun buildEcdsaSignature(algorithmName: String, r: BigInteger, s: BigInteger): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)
        encodeString(out, algorithmName)
        val innerBuf = ByteArrayOutputStream()
        val innerOut = DataOutputStream(innerBuf)
        encodeMpint(innerOut, r)
        encodeMpint(innerOut, s)
        encodeString(out, innerBuf.toByteArray())
        return buf.toByteArray()
    }

    private fun parseDerEcdsaSignature(der: ByteArray): Pair<BigInteger, BigInteger> {
        val reader = DerReader(der)
        return reader.readSequence { seq ->
            seq.readInteger() to seq.readInteger()
        }
    }

    private fun parse(hostKey: ByteArray, sshSig: ByteArray): Pair<SshPublicKey, SshSignature> {
        val pubKey = SshPublicKey(ByteBufferKaitaiStream(hostKey))
        pubKey._read()
        val sig = SshSignature(ByteBufferKaitaiStream(sshSig))
        sig._read()
        return pubKey to sig
    }

    @Test
    fun `verifies valid ecdsa-sha2-nistp256 signature`() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val pub = kp.public as ECPublicKey
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(kp.private)
        sig.update(data)
        val derSig = sig.sign()

        val (r, s) = parseDerEcdsaSignature(derSig)

        val hostKey = buildEcdsaHostKey(pub, "nistp256")
        val sshSig = buildEcdsaSignature("ecdsa-sha2-nistp256", r, s)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertTrue(EcdsaSignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }

    @Test
    fun `rejects invalid ecdsa signature`() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val pub = kp.public as ECPublicKey
        val data = "test exchange hash".toByteArray()

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(kp.private)
        sig.update("wrong data".toByteArray())
        val derSig = sig.sign()

        val (r, s) = parseDerEcdsaSignature(derSig)

        val hostKey = buildEcdsaHostKey(pub, "nistp256")
        val sshSig = buildEcdsaSignature("ecdsa-sha2-nistp256", r, s)
        val (pubKey, sshSigParsed) = parse(hostKey, sshSig)

        assertFalse(EcdsaSignatureAlgorithm.verify(pubKey, sshSigParsed, data))
    }
}
