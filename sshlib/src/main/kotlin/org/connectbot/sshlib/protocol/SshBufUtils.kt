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

package org.connectbot.sshlib.protocol

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.Charset

/**
 * Utility extensions for reading SSH protocol types from a [ByteBuffer].
 */

internal fun ByteBuffer.readString(charset: Charset = Charsets.US_ASCII): String {
    val len = this.int
    if (len < 0 || len > this.remaining()) {
        throw IllegalArgumentException("Invalid string length: $len")
    }
    val bytes = ByteArray(len)
    this.get(bytes)
    return String(bytes, charset)
}

internal fun ByteBuffer.readByteString(): ByteArray {
    val len = this.int
    if (len < 0 || len > this.remaining()) {
        throw IllegalArgumentException("Invalid byte string length: $len")
    }
    val bytes = ByteArray(len)
    this.get(bytes)
    return bytes
}

internal fun ByteBuffer.readMpint(): BigInteger {
    val bytes = readByteString()
    if (bytes.isEmpty()) return BigInteger.ZERO
    return BigInteger(bytes)
}

/**
 * Read an mpint and treat it as an unsigned value.
 * Some implementations might not correctly pad positive values with a zero byte
 * if the MSB is set.
 */
internal fun ByteBuffer.readMpintUnsigned(): BigInteger {
    val bytes = readByteString()
    return BigInteger(1, bytes)
}

/**
 * Utility functions for creating Kaitai Structs for SSH protocol types.
 */

internal fun createAsciiString(str: String): AsciiString = AsciiString().apply {
    setLen(str.length.toLong())
    setValue(str)
    _check()
}

internal fun createUtf8String(str: String): Utf8String {
    val bytes = str.toByteArray(Charsets.UTF_8)
    return Utf8String().apply {
        setLen(bytes.size.toLong())
        setValue(str)
        _check()
    }
}

internal fun createByteString(data: ByteArray): ByteString = ByteString().apply {
    setLenData(data.size.toLong())
    setData(data)
    _check()
}

internal fun createNameList(names: String): NameList {
    val nameList = NameList()
    val entries = NameList.NameEntry()
    entries.set_parent(nameList)
    entries.set_root(nameList)

    if (names.isEmpty()) {
        entries.setData(emptyList())
        nameList.setLenEntries(0)
    } else {
        val list = names.split(",")
        entries.setData(list)
        val contentBytes = names.toByteArray(Charsets.US_ASCII)
        nameList.setLenEntries(contentBytes.size.toLong())
    }

    entries._check()
    nameList.setEntries(entries)
    nameList._check()
    return nameList
}

internal fun createMpint(data: ByteArray): Mpint {
    var start = 0
    while (start < data.size - 1 && data[start] == 0.toByte()) {
        start++
    }

    val needsPadding = (data[start].toInt() and 0x80) != 0

    val formattedLength = data.size - start + if (needsPadding) 1 else 0
    val formatted = ByteArray(formattedLength)

    if (needsPadding) {
        formatted[0] = 0
        System.arraycopy(data, start, formatted, 1, data.size - start)
    } else {
        System.arraycopy(data, start, formatted, 0, data.size - start)
    }

    return Mpint().apply {
        setLenBody(formattedLength.toLong())
        setBody(formatted)
        _check()
    }
}

internal fun createMpint(value: BigInteger): Mpint = createMpint(value.toByteArray())
