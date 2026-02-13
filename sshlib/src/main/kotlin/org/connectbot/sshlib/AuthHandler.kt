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

package org.connectbot.sshlib

/**
 * Callback-driven authentication handler.
 *
 * The library drives the authentication flow per RFC 4252, calling back
 * into this handler for materials. The flow is:
 * none → publickey probe → sign → keyboard-interactive → password
 */
interface AuthHandler {
    /**
     * Called when the server reports which authentication methods are available.
     * Override to observe or log.
     */
    suspend fun onAuthMethodsAvailable(methods: Set<String>) {}

    /**
     * Return public keys to probe. Empty list skips public key auth.
     */
    suspend fun onPublicKeysNeeded(): List<AuthPublicKey>

    /**
     * Called only for keys the server accepted (PK_OK). Return the signature
     * over [dataToSign], or null to skip this key.
     *
     * Use [SshSigning.sign] for local private keys, or return an SSH agent
     * response directly.
     */
    suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray?

    /**
     * Called when the server sends keyboard-interactive prompts.
     * Return responses (one per prompt), or null to skip keyboard-interactive.
     */
    suspend fun onKeyboardInteractivePrompt(
        name: String,
        instruction: String,
        prompts: List<KeyboardInteractiveCallback.Prompt>,
    ): List<String>?

    /**
     * Return the password, or null to skip password auth.
     */
    suspend fun onPasswordNeeded(): String?
}

/**
 * An SSH public key for authentication probing.
 *
 * @param algorithmName SSH algorithm name (e.g., "ssh-ed25519", "rsa-sha2-256")
 * @param publicKeyBlob Wire-format public key blob
 */
data class AuthPublicKey(val algorithmName: String, val publicKeyBlob: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AuthPublicKey
        if (algorithmName != other.algorithmName) return false
        if (!publicKeyBlob.contentEquals(other.publicKeyBlob)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = algorithmName.hashCode()
        result = 31 * result + publicKeyBlob.contentHashCode()
        return result
    }
}
