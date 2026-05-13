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
import org.connectbot.sshlib.crypto.DerReader
import org.connectbot.sshlib.crypto.encodeMpint
import org.connectbot.sshlib.crypto.encodeSshString

/**
 * Packs an SK assertion into the OpenSSH SK signature wire format.
 *
 * The output is what callers should return from
 * [org.connectbot.sshlib.AuthHandler.onSignatureRequest] for an SK
 * public key. The library writes it verbatim into the SSH publickey
 * `USERAUTH_REQUEST` packet's signature field.
 *
 * Format per OpenSSH `PROTOCOL.u2f` §3.2:
 *
 * ```
 * sk-ssh-ed25519@openssh.com:
 *   string  "sk-ssh-ed25519@openssh.com"
 *   string  rawEd25519Signature        (64 bytes)
 *   byte    flags
 *   uint32  counter
 *
 * sk-ecdsa-sha2-nistp256@openssh.com:
 *   string  "sk-ecdsa-sha2-nistp256@openssh.com"
 *   string  sig_material               (mpint r || mpint s, RFC 5656)
 *   byte    flags
 *   uint32  counter
 * ```
 *
 * For ECDSA-P256, [pack] accepts the DER `SEQUENCE { INTEGER r, INTEGER s }`
 * format that CTAP2 returns and converts it to `mpint r || mpint s` internally.
 *
 * What [flags] and [counter] mean (from `PROTOCOL.u2f` §3.2): the FIDO2 device
 * sets `flags = SK_USER_PRESENCE_REQUIRED (0x01)` if user presence was tested
 * and `| SK_USER_VERIFICATION_REQUIRED (0x04)` if user verification was also
 * tested; `counter` is the device's monotonic signature counter. Both come
 * from the CTAP2 GetAssertion response.
 */
public object SkSignatureBlob {

    public const val FLAG_USER_PRESENCE: Byte = 0x01
    public const val FLAG_USER_VERIFICATION: Byte = 0x04

    private const val ED25519_RAW_SIGNATURE_SIZE: Int = 64

    /**
     * Pack an SK assertion into the OpenSSH SK signature blob.
     *
     * @param algorithm SK algorithm.
     * @param rawSignature For [SkAlgorithm.ED25519]: the raw 64-byte Ed25519
     *   signature from the authenticator. For [SkAlgorithm.ECDSA_P256]: the
     *   DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` signature from CTAP2.
     * @param flags Authenticator flags byte (see [FLAG_USER_PRESENCE],
     *   [FLAG_USER_VERIFICATION]).
     * @param counter Authenticator signature counter (big-endian uint32 on the wire).
     * @return The full OpenSSH SK signature wire blob.
     * @throws SshException if [rawSignature] has the wrong size or is malformed.
     */
    public fun pack(
        algorithm: SkAlgorithm,
        rawSignature: ByteArray,
        flags: Byte,
        counter: UInt,
    ): ByteArray {
        val sigMaterial = when (algorithm) {
            SkAlgorithm.ED25519 -> packEd25519Material(rawSignature)
            SkAlgorithm.ECDSA_P256 -> packEcdsaP256MaterialFromDer(rawSignature)
        }
        return encodeSshString(algorithm.sshName.toByteArray(Charsets.US_ASCII)) +
            encodeSshString(sigMaterial) +
            byteArrayOf(flags) +
            encodeUint32BigEndian(counter)
    }

    private fun packEd25519Material(rawSignature: ByteArray): ByteArray {
        if (rawSignature.size != ED25519_RAW_SIGNATURE_SIZE) {
            throw SshException(
                "sk-ssh-ed25519 raw signature must be $ED25519_RAW_SIGNATURE_SIZE bytes, " +
                    "got ${rawSignature.size}",
            )
        }
        return rawSignature
    }

    private fun packEcdsaP256MaterialFromDer(derSignature: ByteArray): ByteArray {
        if (derSignature.isEmpty()) {
            throw SshException("Malformed ECDSA DER signature: empty input")
        }
        val (r, s) = try {
            val reader = DerReader(derSignature)
            val parsed = reader.readSequence { seq ->
                val rInt = seq.readInteger()
                val sInt = seq.readInteger()
                rInt to sInt
            }
            reader.ensureFullyConsumed()
            parsed
        } catch (e: SshException) {
            throw SshException("Malformed ECDSA DER signature: ${e.message}", e)
        } catch (e: java.nio.BufferUnderflowException) {
            throw SshException("Malformed ECDSA DER signature: truncated", e)
        } catch (e: IndexOutOfBoundsException) {
            throw SshException("Malformed ECDSA DER signature: truncated", e)
        }
        if (r.signum() < 0 || s.signum() < 0) {
            throw SshException("ECDSA DER signature components must be non-negative")
        }
        return encodeMpint(r.toByteArray()) + encodeMpint(s.toByteArray())
    }

    private fun encodeUint32BigEndian(value: UInt): ByteArray {
        val intValue = value.toInt()
        return byteArrayOf(
            (intValue ushr 24).toByte(),
            (intValue ushr 16).toByte(),
            (intValue ushr 8).toByte(),
            intValue.toByte(),
        )
    }
}
