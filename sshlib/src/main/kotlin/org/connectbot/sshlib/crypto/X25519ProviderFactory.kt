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

package org.connectbot.sshlib.crypto

import org.slf4j.LoggerFactory
import java.security.Provider
import java.security.Security

internal object X25519ProviderFactory {
    private val logger = LoggerFactory.getLogger(X25519ProviderFactory::class.java)

    private val probePrivateKey = decodeHex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    )
    private val probePublicKey = decodeHex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    )
    private val probePeerPublicKey = decodeHex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    )
    private val probeSharedSecret = decodeHex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    )

    internal val provider: X25519Provider by lazy {
        val platform = selectPlatformProvider(Security.getProviders().toList())
        if (platform != null) {
            logger.debug("Using platform-native X25519 implementation from {}", platform.providerName)
            platform
        } else {
            logger.debug("No platform provider passed the X25519 capability probe; using Tink")
            createTinkProvider()
        }
    }

    internal fun selectPlatformProvider(providers: List<Provider>): PlatformX25519Provider? {
        for (provider in providers) {
            try {
                Class.forName("java.security.spec.XECPrivateKeySpec")
                val candidate = PlatformX25519Provider(provider)
                check(candidate.generatePrivateKey().size == X25519Provider.KEY_SIZE)
                check(candidate.publicFromPrivate(probePrivateKey).contentEquals(probePublicKey))
                check(candidate.computeSharedSecret(probePrivateKey, probePeerPublicKey).contentEquals(probeSharedSecret))
                return candidate
            } catch (e: Exception) {
                logger.trace("JCE provider {} failed the X25519 capability probe", provider.name, e)
            } catch (e: LinkageError) {
                logger.trace("JCE provider {} cannot load the X25519 platform API", provider.name, e)
            }
        }
        return null
    }

    private fun createTinkProvider(): X25519Provider = TinkX25519Provider()

    private fun decodeHex(value: String): ByteArray = value.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
