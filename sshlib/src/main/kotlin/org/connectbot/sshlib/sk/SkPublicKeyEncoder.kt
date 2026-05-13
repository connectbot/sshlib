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
import org.connectbot.sshlib.crypto.encodeSshString

/**
 * Builds OpenSSH SK public-key wire blobs.
 *
 * The output is the byte sequence that appears in `authorized_keys` (base64-encoded
 * after the algorithm name) and in the `public key blob` field of SSH publickey
 * auth requests.
 *
 * Format per OpenSSH `PROTOCOL.u2f` §3.1:
 *
 * ```
 * sk-ssh-ed25519@openssh.com:
 *   string  "sk-ssh-ed25519@openssh.com"
 *   string  rawEd25519PublicKey      (32 bytes)
 *   string  application              (e.g. "ssh:")
 *
 * sk-ecdsa-sha2-nistp256@openssh.com:
 *   string  "sk-ecdsa-sha2-nistp256@openssh.com"
 *   string  "nistp256"
 *   string  ecPoint                  (uncompressed SEC1: 0x04 || X(32) || Y(32), 65 bytes)
 *   string  application
 * ```
 */
public object SkPublicKeyEncoder {

    private const val ED25519_RAW_KEY_SIZE: Int = 32
    private const val P256_FIELD_SIZE: Int = 32
    private const val P256_POINT_SIZE: Int = 1 + 2 * P256_FIELD_SIZE
    private const val P256_CURVE_IDENTIFIER: String = "nistp256"

    /**
     * Build the SK public-key wire blob.
     *
     * @param algorithm SK algorithm.
     * @param rawKey For [SkAlgorithm.ED25519] the 32-byte raw Ed25519 public key.
     *   For [SkAlgorithm.ECDSA_P256] the 65-byte uncompressed SEC1 point
     *   (`0x04 || X(32) || Y(32)`).
     * @param application Relying-party identifier (e.g. `"ssh:"`).
     * @throws SshException if [rawKey] has the wrong size for the algorithm,
     *   or if the ECDSA point is malformed.
     */
    public fun encode(algorithm: SkAlgorithm, rawKey: ByteArray, application: String): ByteArray = when (algorithm) {
        SkAlgorithm.ED25519 -> encodeEd25519(rawKey, application)
        SkAlgorithm.ECDSA_P256 -> encodeEcdsaP256(rawKey, application)
    }

    private fun encodeEd25519(rawKey: ByteArray, application: String): ByteArray {
        if (rawKey.size != ED25519_RAW_KEY_SIZE) {
            throw SshException(
                "sk-ssh-ed25519 raw key must be $ED25519_RAW_KEY_SIZE bytes, got ${rawKey.size}",
            )
        }
        return encodeSshString(SkAlgorithm.ED25519.sshName.toByteArray(Charsets.US_ASCII)) +
            encodeSshString(rawKey) +
            encodeSshString(application.toByteArray(Charsets.UTF_8))
    }

    private fun encodeEcdsaP256(ecPoint: ByteArray, application: String): ByteArray {
        if (ecPoint.size != P256_POINT_SIZE || ecPoint[0] != 0x04.toByte()) {
            throw SshException(
                "sk-ecdsa-sha2-nistp256 EC point must be $P256_POINT_SIZE bytes starting with 0x04, " +
                    "got ${ecPoint.size} bytes${if (ecPoint.isNotEmpty()) " starting with 0x%02x".format(ecPoint[0]) else ""}",
            )
        }
        return encodeSshString(SkAlgorithm.ECDSA_P256.sshName.toByteArray(Charsets.US_ASCII)) +
            encodeSshString(P256_CURVE_IDENTIFIER.toByteArray(Charsets.US_ASCII)) +
            encodeSshString(ecPoint) +
            encodeSshString(application.toByteArray(Charsets.UTF_8))
    }
}
