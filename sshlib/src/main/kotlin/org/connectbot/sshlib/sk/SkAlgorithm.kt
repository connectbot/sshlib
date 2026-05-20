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

/**
 * OpenSSH FIDO2 / Security Key public-key algorithms.
 *
 * These algorithms are used for SSH authentication backed by a hardware
 * authenticator (CTAP2 device). The library does not perform CTAP2 signing
 * itself; callers integrate with their own FIDO2 stack and surface the
 * resulting signature via [org.connectbot.sshlib.AuthHandler.onSignatureRequest].
 *
 * See OpenSSH's `PROTOCOL.u2f` and `draft-miller-ssh-agent` for the on-wire
 * formats.
 */
public enum class SkAlgorithm(public val sshName: String) {
    /** Ed25519 hardware-backed key (`sk-ssh-ed25519@openssh.com`). */
    ED25519("sk-ssh-ed25519@openssh.com"),

    /** ECDSA P-256 hardware-backed key (`sk-ecdsa-sha2-nistp256@openssh.com`). */
    ECDSA_P256("sk-ecdsa-sha2-nistp256@openssh.com"),
    ;

    public companion object {
        /** Look up an [SkAlgorithm] by its on-wire SSH name, or `null` if unrecognised. */
        public fun fromSshName(name: String): SkAlgorithm? = entries.firstOrNull { it.sshName == name }

        /** `true` if [name] is one of the SK algorithm names handled by this library. */
        public fun isSkAlgorithm(name: String): Boolean = fromSshName(name) != null
    }
}

/**
 * Decoded SK public key.
 *
 * @property algorithm Which SK algorithm this key uses.
 * @property rawKey Algorithm-specific raw public key bytes. For [SkAlgorithm.ED25519]
 *   this is the 32-byte raw Ed25519 public key. For [SkAlgorithm.ECDSA_P256] this is
 *   the uncompressed SEC1 point (`0x04 || X(32) || Y(32)`, 65 bytes).
 * @property application The relying-party identifier the key was bound to (typically
 *   `"ssh:"` for keys generated with `ssh-keygen -t ed25519-sk`).
 */
public data class SkPublicKey(
    val algorithm: SkAlgorithm,
    val rawKey: ByteArray,
    val application: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SkPublicKey
        if (algorithm != other.algorithm) return false
        if (!rawKey.contentEquals(other.rawKey)) return false
        if (application != other.application) return false
        return true
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + rawKey.contentHashCode()
        result = 31 * result + application.hashCode()
        return result
    }
}
