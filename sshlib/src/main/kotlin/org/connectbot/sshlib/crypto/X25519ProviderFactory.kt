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

package org.connectbot.sshlib.crypto

import org.slf4j.LoggerFactory
import java.security.KeyPairGenerator

internal object X25519ProviderFactory {
    private val logger = LoggerFactory.getLogger(X25519ProviderFactory::class.java)

    internal val provider: X25519Provider by lazy {
        if (isPlatformNativeAvailable()) {
            try {
                val p = PlatformX25519Provider()
                logger.debug("Using platform-native X25519 implementation")
                p
            } catch (e: Exception) {
                logger.debug("Platform X25519 class loading failed, falling back to Tink")
                createTinkProvider()
            }
        } else {
            logger.debug("Using Tink X25519 implementation")
            createTinkProvider()
        }
    }

    private fun isPlatformNativeAvailable(): Boolean = try {
        KeyPairGenerator.getInstance("X25519")
        true
    } catch (_: Exception) {
        false
    }

    private fun createTinkProvider(): X25519Provider = TinkX25519Provider()
}
