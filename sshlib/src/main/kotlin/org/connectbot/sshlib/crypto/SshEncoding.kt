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

/**
 * Encode a BigInteger-style byte array as an SSH mpint (RFC 4251 section 5).
 *
 * Returns uint32(length) || body, where body has leading zeros stripped and
 * a 0x00 prepended if the high bit is set (to keep the value positive).
 */
fun encodeMpint(value: ByteArray): ByteArray {
    var start = 0
    while (start < value.size - 1 && value[start] == 0.toByte()) {
        start++
    }

    val needsPadding = value[start].toInt() and 0x80 != 0
    val bodyLen = value.size - start + if (needsPadding) 1 else 0

    val result = ByteArray(4 + bodyLen)
    result[0] = (bodyLen shr 24).toByte()
    result[1] = (bodyLen shr 16).toByte()
    result[2] = (bodyLen shr 8).toByte()
    result[3] = bodyLen.toByte()

    if (needsPadding) {
        result[4] = 0
        System.arraycopy(value, start, result, 5, value.size - start)
    } else {
        System.arraycopy(value, start, result, 4, value.size - start)
    }
    return result
}

/**
 * Encode a raw byte array as an SSH string (RFC 4251 section 5).
 *
 * Returns uint32(length) || data.
 */
fun encodeSshString(value: ByteArray): ByteArray {
    val result = ByteArray(4 + value.size)
    result[0] = (value.size shr 24).toByte()
    result[1] = (value.size shr 16).toByte()
    result[2] = (value.size shr 8).toByte()
    result[3] = value.size.toByte()
    System.arraycopy(value, 0, result, 4, value.size)
    return result
}
