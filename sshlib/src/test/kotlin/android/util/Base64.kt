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

package android.util

class Base64 {
    companion object {
        @JvmField
        val NO_WRAP: Int = 2

        @JvmField
        val NO_PADDING: Int = 1

        @JvmField
        val DEFAULT: Int = 0

        @JvmStatic
        fun encodeToString(data: ByteArray, flags: Int): String {
            val encoder = if ((flags and NO_PADDING) != 0) {
                java.util.Base64.getEncoder().withoutPadding()
            } else {
                java.util.Base64.getEncoder()
            }
            return encoder.encodeToString(data)
        }

        @JvmStatic
        fun decode(data: String, flags: Int): ByteArray = java.util.Base64.getDecoder().decode(data)
    }
}
