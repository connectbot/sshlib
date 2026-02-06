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

import org.connectbot.sshlib.crypto.PrivateKeyReader
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.crypto.SshPublicKeyEncoder

/**
 * Utility for signing authentication data with local private keys.
 *
 * Use from [AuthHandler.onSignatureRequest] when you have the private key
 * available locally. For SSH agent forwarding, return the agent's response
 * directly instead.
 */
object SshSigning {
    /**
     * Sign authentication data using a private key.
     *
     * @param algorithmName SSH signature algorithm (e.g., "ssh-ed25519", "rsa-sha2-256")
     * @param privateKeyData PEM or OpenSSH private key contents
     * @param passphrase Key passphrase, or null if unencrypted
     * @param dataToSign The data to sign (as provided by [AuthHandler.onSignatureRequest])
     * @return SSH-encoded signature blob
     */
    fun sign(
        algorithmName: String,
        privateKeyData: String,
        passphrase: String?,
        dataToSign: ByteArray
    ): ByteArray {
        val privateKey = PrivateKeyReader.read(privateKeyData, passphrase)
        val sigEntry = SignatureEntry.fromSshName(algorithmName)
            ?: throw SshException("Unknown signature algorithm: $algorithmName")
        return sigEntry.algorithm.sign(algorithmName, privateKey.jcaKeyPair.private, dataToSign)
    }

    /**
     * Sign authentication data using a private key.
     *
     * @param algorithmName SSH signature algorithm (e.g., "ssh-ed25519", "rsa-sha2-256")
     * @param privateKeyData PEM or OpenSSH private key contents as bytes
     * @param passphrase Key passphrase, or null if unencrypted
     * @param dataToSign The data to sign (as provided by [AuthHandler.onSignatureRequest])
     * @return SSH-encoded signature blob
     */
    fun sign(
        algorithmName: String,
        privateKeyData: ByteArray,
        passphrase: String?,
        dataToSign: ByteArray
    ): ByteArray = sign(algorithmName, String(privateKeyData, Charsets.UTF_8), passphrase, dataToSign)

    /**
     * Extract the [AuthPublicKey] from a private key for use with [AuthHandler.onPublicKeysNeeded].
     *
     * @param algorithmName SSH algorithm name (e.g., "ssh-ed25519", "rsa-sha2-256")
     * @param privateKeyData PEM or OpenSSH private key contents
     * @param passphrase Key passphrase, or null if unencrypted
     * @return The corresponding public key for probing
     */
    fun getPublicKey(
        algorithmName: String,
        privateKeyData: String,
        passphrase: String?
    ): AuthPublicKey {
        val privateKey = PrivateKeyReader.read(privateKeyData, passphrase)
        val blob = SshPublicKeyEncoder.encode(privateKey.jcaKeyPair, privateKey.keyType)
        return AuthPublicKey(algorithmName, blob)
    }

    /**
     * Extract the [AuthPublicKey] from a private key for use with [AuthHandler.onPublicKeysNeeded].
     *
     * @param algorithmName SSH algorithm name (e.g., "ssh-ed25519", "rsa-sha2-256")
     * @param privateKeyData PEM or OpenSSH private key contents as bytes
     * @param passphrase Key passphrase, or null if unencrypted
     * @return The corresponding public key for probing
     */
    fun getPublicKey(
        algorithmName: String,
        privateKeyData: ByteArray,
        passphrase: String?
    ): AuthPublicKey = getPublicKey(algorithmName, String(privateKeyData, Charsets.UTF_8), passphrase)
}
