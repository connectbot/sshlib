/*
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

package org.connectbot.sshlib.sk

import org.connectbot.sshlib.SshException

/**
 * Parses OpenSSH SK public-key wire blobs into an [SkPublicKey].
 *
 * This is the inverse of [SkPublicKeyEncoder.encode]. Callers that already
 * have raw key bytes can skip this; the decoder is provided so callers that
 * parse `authorized_keys` or `ssh-keygen -t *-sk` files (which embed the
 * pubkey blob inside an OpenSSH private-key envelope) don't have to write
 * SSH-string framing logic themselves.
 *
 * Strict: the entire input must be consumed.
 */
public object SkPublicKeyDecoder {

    private const val ED25519_RAW_KEY_SIZE: Int = 32
    private const val P256_FIELD_SIZE: Int = 32
    private const val P256_POINT_SIZE: Int = 1 + 2 * P256_FIELD_SIZE
    private const val P256_CURVE_IDENTIFIER: String = "nistp256"

    /**
     * Decode an SK public-key wire blob.
     *
     * @throws SshException if the blob is malformed, has trailing bytes, or
     *   uses an algorithm name that is not one of the known SK algorithms.
     */
    public fun decode(blob: ByteArray): SkPublicKey {
        val reader = SshWireReader(blob)
        val algoBytes = reader.readSshString()
        val algoName = algoBytes.toString(Charsets.US_ASCII)
        val algorithm = SkAlgorithm.fromSshName(algoName)
            ?: throw SshException("Not an SK public key blob: algorithm = \"$algoName\"")

        val result = when (algorithm) {
            SkAlgorithm.ED25519 -> decodeEd25519Body(reader)
            SkAlgorithm.ECDSA_P256 -> decodeEcdsaP256Body(reader)
        }

        reader.expectEnd("trailing bytes after sk public key blob")
        return result
    }

    private fun decodeEd25519Body(reader: SshWireReader): SkPublicKey {
        val rawKey = reader.readSshString()
        if (rawKey.size != ED25519_RAW_KEY_SIZE) {
            throw SshException(
                "sk-ssh-ed25519 raw key must be $ED25519_RAW_KEY_SIZE bytes, got ${rawKey.size}",
            )
        }
        val application = reader.readSshString().toString(Charsets.UTF_8)
        return SkPublicKey(SkAlgorithm.ED25519, rawKey, application)
    }

    private fun decodeEcdsaP256Body(reader: SshWireReader): SkPublicKey {
        val curveBytes = reader.readSshString()
        val curveName = curveBytes.toString(Charsets.US_ASCII)
        if (curveName != P256_CURVE_IDENTIFIER) {
            throw SshException(
                "sk-ecdsa-sha2-nistp256 expects curve \"$P256_CURVE_IDENTIFIER\", got \"$curveName\"",
            )
        }
        val ecPoint = reader.readSshString()
        if (ecPoint.size != P256_POINT_SIZE || ecPoint[0] != 0x04.toByte()) {
            throw SshException(
                "sk-ecdsa-sha2-nistp256 EC point must be $P256_POINT_SIZE bytes starting with 0x04, " +
                    "got ${ecPoint.size} bytes",
            )
        }
        val application = reader.readSshString().toString(Charsets.UTF_8)
        return SkPublicKey(SkAlgorithm.ECDSA_P256, ecPoint, application)
    }
}

/** Internal SSH-wire string reader (uint32-length prefixed). Not part of the public API. */
internal class SshWireReader(private val buffer: ByteArray) {
    private var offset: Int = 0

    fun readSshString(): ByteArray {
        if (offset + 4 > buffer.size) {
            throw SshException("Truncated SSH string at offset $offset (need 4 length bytes)")
        }
        val len = ((buffer[offset].toInt() and 0xff) shl 24) or
            ((buffer[offset + 1].toInt() and 0xff) shl 16) or
            ((buffer[offset + 2].toInt() and 0xff) shl 8) or
            (buffer[offset + 3].toInt() and 0xff)
        if (len < 0) {
            throw SshException("SSH string length overflow at offset $offset: $len")
        }
        if (offset + 4 + len > buffer.size) {
            throw SshException(
                "Truncated SSH string at offset $offset: declared $len bytes, have ${buffer.size - offset - 4}",
            )
        }
        val out = buffer.copyOfRange(offset + 4, offset + 4 + len)
        offset += 4 + len
        return out
    }

    fun expectEnd(message: String) {
        if (offset != buffer.size) {
            throw SshException("$message (${buffer.size - offset} bytes remaining)")
        }
    }
}
