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

package org.connectbot.sshlib.sk

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.protocol.SkEcdsaP256PublicKeyBlob
import org.connectbot.sshlib.protocol.SkEd25519PublicKeyBlob
import org.connectbot.sshlib.protocol.SshPublicKey

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
        val stream = ByteBufferKaitaiStream(blob)
        val kaitai = SshPublicKey(stream)
        try {
            kaitai._read()
            if (!stream.isEof) {
                throw SshException("Trailing bytes after SK public key blob")
            }
        } catch (e: Exception) {
            if (e is SshException) throw e
            throw SshException("Malformed SK public key blob: ${e.message}", e)
        }

        val algoName = kaitai.algorithmName()
        val algorithm = SkAlgorithm.fromSshName(algoName)
            ?: throw SshException("Not an SK public key blob: algorithm = \"$algoName\"")

        return when (val keyBlob = kaitai.keyBlob()) {
            is SkEd25519PublicKeyBlob -> {
                val rawKey = keyBlob.publicKey().data()
                if (rawKey.size != ED25519_RAW_KEY_SIZE) {
                    throw SshException(
                        "sk-ssh-ed25519 raw key must be $ED25519_RAW_KEY_SIZE bytes, got ${rawKey.size}",
                    )
                }
                val application = keyBlob.application().data().toString(Charsets.UTF_8)
                SkPublicKey(SkAlgorithm.ED25519, rawKey, application)
            }

            is SkEcdsaP256PublicKeyBlob -> {
                val ecPoint = keyBlob.publicKey().data()
                if (ecPoint.size != P256_POINT_SIZE || ecPoint[0] != 0x04.toByte()) {
                    throw SshException(
                        "sk-ecdsa-sha2-nistp256 EC point must be $P256_POINT_SIZE bytes starting with 0x04, " +
                            "got ${ecPoint.size} bytes",
                    )
                }
                val application = keyBlob.application().data().toString(Charsets.UTF_8)
                SkPublicKey(SkAlgorithm.ECDSA_P256, ecPoint, application)
            }

            else -> throw SshException("Unexpected key blob type for $algoName")
        }
    }
}
