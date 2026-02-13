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
import org.connectbot.sshlib.crypto.inferKeyType
import java.security.KeyPair
import java.security.PublicKey

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
        dataToSign: ByteArray,
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
        dataToSign: ByteArray,
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
        passphrase: String?,
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
        passphrase: String?,
    ): AuthPublicKey = getPublicKey(algorithmName, String(privateKeyData, Charsets.UTF_8), passphrase)

    /**
     * Encode a [KeyPair]'s public key to an [AuthPublicKey] for use with
     * [AuthHandler.onPublicKeysNeeded].
     *
     * The SSH algorithm name is inferred from the key type (e.g., Ed25519 → "ssh-ed25519",
     * RSA → "ssh-rsa"). For RSA keys that need a specific signature algorithm like
     * "rsa-sha2-256", construct the [AuthPublicKey] with the desired algorithm name
     * using the returned blob.
     *
     * @param keyPair JCA key pair
     * @return The corresponding [AuthPublicKey]
     */
    fun encodePublicKey(keyPair: KeyPair): AuthPublicKey {
        val keyType = inferKeyType(keyPair)
        val blob = SshPublicKeyEncoder.encode(keyPair, keyType)
        return AuthPublicKey(keyType, blob)
    }

    /**
     * Sign authentication data using a JCA [KeyPair].
     *
     * @param algorithmName SSH signature algorithm (e.g., "ssh-ed25519", "rsa-sha2-256")
     * @param keyPair JCA key pair containing the private key
     * @param dataToSign The data to sign (as provided by [AuthHandler.onSignatureRequest])
     * @return SSH-encoded signature blob
     */
    fun signWithKeyPair(
        algorithmName: String,
        keyPair: KeyPair,
        dataToSign: ByteArray,
    ): ByteArray {
        val sigEntry = SignatureEntry.fromSshName(algorithmName)
            ?: throw SshException("Unknown signature algorithm: $algorithmName")
        return sigEntry.algorithm.sign(algorithmName, keyPair.private, dataToSign)
    }

    /**
     * Encode a [PublicKey] to its raw SSH wire-format public key blob.
     *
     * The key type is inferred from the JCA key (e.g., Ed25519 → "ssh-ed25519",
     * RSA → "ssh-rsa").
     *
     * @param publicKey JCA public key
     * @return SSH wire-format public key blob
     */
    fun encodePublicKeyBlob(publicKey: PublicKey): ByteArray {
        val keyType = inferKeyType(publicKey)
        return SshPublicKeyEncoder.encode(publicKey, keyType)
    }
}
