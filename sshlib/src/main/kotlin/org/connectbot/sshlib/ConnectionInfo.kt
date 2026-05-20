/*
 * ConnectBot SSH Library
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

import org.connectbot.sshlib.crypto.KexEntry

/**
 * Negotiated algorithm details for an established SSH connection.
 *
 * Available via [SshClient.connectionInfo] after a successful [SshClient.connect].
 */
data class ConnectionInfo(
    val kexAlgorithm: String,
    val serverHostKeyAlgorithm: String,
    val encryptionAlgorithmC2S: String,
    val encryptionAlgorithmS2C: String,
    /** Null when the cipher is AEAD (no separate MAC needed). */
    val macAlgorithmC2S: String?,
    /** Null when the cipher is AEAD (no separate MAC needed). */
    val macAlgorithmS2C: String?,
) {
    /**
     * True if the key exchange algorithm is post-quantum secure.
     *
     * Currently only `mlkem768x25519-sha256` qualifies.
     */
    val isPostQuantumSecure: Boolean
        get() = KexEntry.fromSshName(kexAlgorithm)?.isPostQuantum == true
}
