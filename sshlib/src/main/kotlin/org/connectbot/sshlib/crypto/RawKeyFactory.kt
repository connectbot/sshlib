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

package org.connectbot.sshlib.crypto

import org.connectbot.sshlib.crypto.ed25519.Ed25519Provider
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec

/**
 * Performs raw key conversion against providers that have demonstrated support
 * for the requested key specification.
 *
 * Some Android builds advertise raw-key algorithms from AndroidKeyStore even
 * though that provider only accepts keystore-backed keys. JCA's unpinned lookup
 * can therefore resolve successfully and fail only when the key is converted.
 */
internal object RawKeyFactory {
    private val ed25519FallbackProvider by lazy { Ed25519Provider() }

    fun generatePublic(
        algorithm: String,
        keySpec: KeySpec,
        providers: List<Provider> = installedProviders(algorithm),
    ): PublicKey = withFactory(algorithm, providers) { it.generatePublic(keySpec) }

    fun generatePrivate(
        algorithm: String,
        keySpec: KeySpec,
        providers: List<Provider> = installedProviders(algorithm),
    ): PrivateKey = withFactory(algorithm, providers) { it.generatePrivate(keySpec) }

    fun generateKeyPair(
        algorithm: String,
        publicKeySpec: KeySpec,
        privateKeySpec: KeySpec,
        providers: List<Provider> = installedProviders(algorithm),
    ): KeyPair = withFactory(algorithm, providers) {
        KeyPair(it.generatePublic(publicKeySpec), it.generatePrivate(privateKeySpec))
    }

    private fun installedProviders(algorithm: String): List<Provider> {
        val installed = Security.getProviders().toMutableList()
        if (algorithm.equals(Ed25519Provider.KEY_ALGORITHM, ignoreCase = true) &&
            installed.none { it.name == Ed25519Provider.NAME }
        ) {
            installed += ed25519FallbackProvider
        }
        return installed
    }

    private inline fun <T> withFactory(
        algorithm: String,
        providers: List<Provider>,
        operation: (KeyFactory) -> T,
    ): T {
        var lastFailure: GeneralSecurityException? = null
        for (provider in providers) {
            try {
                return operation(KeyFactory.getInstance(algorithm, provider))
            } catch (e: GeneralSecurityException) {
                lastFailure = e
            }
        }

        throw InvalidKeySpecException(
            "No JCE provider could convert raw $algorithm key material",
            lastFailure,
        )
    }
}
