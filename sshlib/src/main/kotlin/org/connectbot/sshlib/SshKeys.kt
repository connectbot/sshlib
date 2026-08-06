/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

import org.connectbot.sshlib.crypto.OpenSshKeyWriter
import org.connectbot.sshlib.crypto.PemKeyWriter
import org.connectbot.sshlib.crypto.PrivateKeyReader
import java.security.KeyPair

/**
 * Key management utilities for SSH private keys.
 *
 * Provides decoding/encoding of private keys in PEM, PKCS#8, and OpenSSH formats,
 * and Ed25519 JCA provider registration for platforms that lack native support.
 */
object SshKeys {

    /**
     * Decode a private key from PEM, PKCS#8, or OpenSSH format.
     *
     * Supports RSA, ECDSA (nistp256/384/521), and Ed25519 keys in:
     * - OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`)
     * - PEM/PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`)
     * - PEM/SEC1 EC (`BEGIN EC PRIVATE KEY`)
     * - PKCS#8 (`BEGIN PRIVATE KEY`)
     *
     * @param pem Private key contents as a string
     * @param password Passphrase for encrypted keys, or null if unencrypted
     * @return JCA [KeyPair] containing both public and private keys
     * @throws SshException if the key format is unrecognized or decryption fails
     */
    fun decodePemPrivateKey(pem: String, password: String? = null): KeyPair = PrivateKeyReader.read(pem, password).jcaKeyPair

    /**
     * Encode a [KeyPair] to PEM format.
     *
     * - RSA keys are encoded as PKCS#1 (`BEGIN RSA PRIVATE KEY`)
     * - EC keys are encoded as SEC1 (`BEGIN EC PRIVATE KEY`)
     * - Ed25519 keys are encoded as PKCS#8 (`BEGIN PRIVATE KEY`)
     *
     * @param keyPair JCA key pair to encode
     * @param password Optional passphrase to encrypt the key. RSA and EC use legacy
     *   PEM AES-256-CBC encryption; Ed25519 uses PBES2 encrypted PKCS#8.
     * @return PEM-encoded private key string
     * @throws SshException if the key type is unsupported
     */
    fun encodePemPrivateKey(keyPair: KeyPair, password: String? = null): String = PemKeyWriter.write(keyPair, password)

    /**
     * Encode a [KeyPair] to OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`).
     *
     * @param keyPair JCA key pair to encode
     * @param password Optional passphrase to encrypt the key (AES-256-CTR with bcrypt KDF)
     * @return OpenSSH-formatted private key string
     * @throws SshException if the key type is unsupported
     */
    fun encodeOpenSshPrivateKey(keyPair: KeyPair, password: String? = null): String = OpenSshKeyWriter.write(keyPair, password)

    /**
     * Ed25519 support is now selected automatically without changing the global
     * JCE provider list.
     */
    @Deprecated("Ed25519 support is selected automatically")
    fun ensureEd25519Support() = Unit
}
