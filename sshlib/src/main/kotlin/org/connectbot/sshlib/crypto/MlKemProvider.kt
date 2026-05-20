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

package org.connectbot.sshlib.crypto

import java.io.IOException

internal data class MlKemKeyPair(val publicKey: ByteArray, val privateKey: ByteArray)
internal data class MlKemEncapsulationResult(val ciphertext: ByteArray, val sharedSecret: ByteArray)

internal interface MlKemProvider {
    @Throws(IOException::class)
    fun generateKeyPair(): MlKemKeyPair

    @Throws(IOException::class)
    fun encapsulate(publicKey: ByteArray): MlKemEncapsulationResult

    @Throws(IOException::class)
    fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray
}
