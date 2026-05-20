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

import org.connectbot.sshlib.AuthPublicKey

/**
 * Convenience entry points for wiring SK keys into the
 * [org.connectbot.sshlib.AuthHandler] flow.
 *
 * Typical caller flow (caller owns the CTAP2 stack):
 *
 * ```kotlin
 * // 1. From your stored SK key data, build an AuthPublicKey:
 * val authKey = SkAuthHelpers.buildAuthPublicKey(
 *     algorithm = SkAlgorithm.ED25519,
 *     rawKey = storedRawEd25519PubKey,        // 32 bytes
 *     application = "ssh:",                   // RP id the credential is bound to
 * )
 *
 * // 2. Return it from AuthHandler.onPublicKeysNeeded():
 * override suspend fun onPublicKeysNeeded() = listOf(authKey)
 *
 * // 3. In AuthHandler.onSignatureRequest(), call your CTAP2 stack with
 * //    clientDataHash = SHA-256(dataToSign), then return SkSignatureBlob.pack(...).
 * override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray {
 *     val clientDataHash = sha256(dataToSign)
 *     val assertion = myCtap2.getAssertion(rpId = "ssh:", credentialId = ..., clientDataHash)
 *     return SkSignatureBlob.pack(
 *         algorithm = SkAlgorithm.ED25519,
 *         rawSignature = assertion.signature,     // raw 64 bytes for Ed25519, DER for ECDSA-P256
 *         flags = assertion.flags,                // 0x01 = UP, |0x04 if UV
 *         counter = assertion.counter,
 *     )
 * }
 * ```
 */
public object SkAuthHelpers {

    /**
     * Build an [AuthPublicKey] for an SK credential, suitable for returning from
     * [org.connectbot.sshlib.AuthHandler.onPublicKeysNeeded].
     *
     * The public-key blob is encoded per [SkPublicKeyEncoder].
     */
    public fun buildAuthPublicKey(
        algorithm: SkAlgorithm,
        rawKey: ByteArray,
        application: String,
    ): AuthPublicKey = AuthPublicKey(
        algorithmName = algorithm.sshName,
        publicKeyBlob = SkPublicKeyEncoder.encode(algorithm, rawKey, application),
    )
}
