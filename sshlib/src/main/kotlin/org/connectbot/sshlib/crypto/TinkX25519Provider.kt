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

import com.google.crypto.tink.subtle.X25519

internal class TinkX25519Provider : X25519Provider {
    override fun generatePrivateKey(): ByteArray = X25519.generatePrivateKey()

    override fun publicFromPrivate(privateKey: ByteArray): ByteArray =
        X25519.publicFromPrivate(privateKey)

    override fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray =
        X25519.computeSharedSecret(privateKey, publicKey)
}
