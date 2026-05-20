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

import java.util.Base64

/**
 * Base64 compatibility adapter supporting both JVM and Android API 24+.
 *
 * On Android below API 26, `Base64` is unavailable. This object detects
 * `android.util.Base64` at runtime via reflection and delegates to it; otherwise
 * falls back to `Base64`.
 */
internal object Base64Compat {

    private val delegate: Delegate = runCatching {
        val cls = Class.forName("android.util.Base64")
        AndroidDelegate(cls)
    }.getOrElse {
        JvmDelegate()
    }

    fun encode(data: ByteArray): String = delegate.encode(data)

    fun encodeWithPadding(data: ByteArray): String = delegate.encodeWithPadding(data)

    fun decode(data: String): ByteArray = delegate.decode(data)

    private interface Delegate {
        fun encode(data: ByteArray): String
        fun encodeWithPadding(data: ByteArray): String
        fun decode(data: String): ByteArray
    }

    private class JvmDelegate : Delegate {
        private val encoder = Base64.getEncoder()
        private val encoderNoPad = Base64.getEncoder().withoutPadding()
        private val decoder = Base64.getDecoder()

        override fun encode(data: ByteArray): String = encoderNoPad.encodeToString(data)
        override fun encodeWithPadding(data: ByteArray): String = encoder.encodeToString(data)
        override fun decode(data: String): ByteArray = decoder.decode(data)
    }

    private class AndroidDelegate(cls: Class<*>) : Delegate {
        // android.util.Base64 flag constants
        private val NO_WRAP = cls.getField("NO_WRAP").getInt(null)
        private val NO_PADDING = cls.getField("NO_PADDING").getInt(null)
        private val DEFAULT = cls.getField("DEFAULT").getInt(null)

        private val encodeMethod = cls.getMethod("encodeToString", ByteArray::class.java, Int::class.java)
        private val decodeMethod = cls.getMethod("decode", String::class.java, Int::class.java)

        override fun encode(data: ByteArray): String = encodeMethod.invoke(null, data, NO_WRAP or NO_PADDING) as String

        override fun encodeWithPadding(data: ByteArray): String = encodeMethod.invoke(null, data, NO_WRAP) as String

        override fun decode(data: String): ByteArray = decodeMethod.invoke(null, data, DEFAULT) as ByteArray
    }
}
