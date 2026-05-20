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

import java.lang.reflect.Constructor
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object ChaCha20ParamFactory {
    private val usesChaCha20ParameterSpec: Boolean
    private val constructor: Constructor<*>?

    init {
        var ctor: Constructor<*>? = null
        var useSpec = false

        try {
            val clazz = Class.forName("javax.crypto.spec.ChaCha20ParameterSpec")
            ctor = clazz.getConstructor(ByteArray::class.java, Int::class.javaPrimitiveType)

            val testNonce = ByteArray(12)
            val testKey = ByteArray(32)
            val testParams = ctor.newInstance(testNonce, 0) as AlgorithmParameterSpec
            val testKeySpec = SecretKeySpec(testKey, "ChaCha20")

            val testCipher = Cipher.getInstance("ChaCha20/None/NoPadding")
            testCipher.init(Cipher.DECRYPT_MODE, testKeySpec, testParams)

            useSpec = true
        } catch (_: Exception) {
        }

        usesChaCha20ParameterSpec = useSpec
        constructor = if (useSpec) ctor else null
    }

    fun create(nonce: ByteArray, counter: Int): AlgorithmParameterSpec {
        if (usesChaCha20ParameterSpec && constructor != null) {
            return constructor.newInstance(nonce.clone(), counter) as AlgorithmParameterSpec
        }
        return IvParameterSpec(nonce.clone())
    }

    fun usesChaCha20ParameterSpec(): Boolean = usesChaCha20ParameterSpec
}
