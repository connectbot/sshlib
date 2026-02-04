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

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStruct

/**
 * Serialize a Kaitai struct to a byte array.
 */
fun KaitaiStruct.ReadWrite.toByteArray(): ByteArray {
    _check()
    val io = ByteBufferKaitaiStream(1024 * 16)
    _write(io)
    val size = io.pos()
    io.seek(0)
    return io.readBytes(size.toLong())
}
