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

package org.connectbot.sshlib.client.sftp

import org.connectbot.sshlib.SftpAttributes
import java.nio.ByteBuffer

/**
 * Internal parser/serializer for SFTPv3 ATTRS structure.
 *
 * The ATTRS structure uses a flags field to indicate which subsequent
 * fields are present (draft-ietf-secsh-filexfer-02 section 5).
 *
 * Flags:
 * - SSH_FILEXFER_ATTR_SIZE       (0x00000001): size is present
 * - SSH_FILEXFER_ATTR_UIDGID     (0x00000002): uid and gid are present
 * - SSH_FILEXFER_ATTR_PERMISSIONS(0x00000004): permissions is present
 * - SSH_FILEXFER_ATTR_ACMODTIME  (0x00000008): atime and mtime are present
 * - SSH_FILEXFER_ATTR_EXTENDED   (0x80000000): extended attributes present
 */
internal object SftpFileAttributes {
    private const val SSH_FILEXFER_ATTR_SIZE = 0x00000001
    private const val SSH_FILEXFER_ATTR_UIDGID = 0x00000002
    private const val SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
    private const val SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008
    private const val SSH_FILEXFER_ATTR_EXTENDED = 0x80000000.toInt()

    /**
     * Parse ATTRS from a ByteBuffer at its current position.
     */
    fun decode(buf: ByteBuffer): SftpAttributes {
        val flags = buf.int
        val size = if (flags and SSH_FILEXFER_ATTR_SIZE != 0) buf.long else null
        val uid = if (flags and SSH_FILEXFER_ATTR_UIDGID != 0) buf.int else null
        val gid = if (flags and SSH_FILEXFER_ATTR_UIDGID != 0) buf.int else null
        val permissions = if (flags and SSH_FILEXFER_ATTR_PERMISSIONS != 0) buf.int else null
        val atime = if (flags and SSH_FILEXFER_ATTR_ACMODTIME != 0) buf.int else null
        val mtime = if (flags and SSH_FILEXFER_ATTR_ACMODTIME != 0) buf.int else null

        // Skip extended attributes if present
        if (flags and SSH_FILEXFER_ATTR_EXTENDED != 0) {
            val extCount = buf.int
            repeat(extCount) {
                val typeLen = buf.int
                buf.position(buf.position() + typeLen) // skip type string
                val dataLen = buf.int
                buf.position(buf.position() + dataLen) // skip data string
            }
        }

        return SftpAttributes(
            size = size,
            uid = uid,
            gid = gid,
            permissions = permissions,
            atime = atime,
            mtime = mtime
        )
    }

    /**
     * Encode ATTRS to a byte array.
     */
    fun encode(attrs: SftpAttributes): ByteArray {
        var flags = 0
        if (attrs.size != null) flags = flags or SSH_FILEXFER_ATTR_SIZE
        if (attrs.uid != null || attrs.gid != null) flags = flags or SSH_FILEXFER_ATTR_UIDGID
        if (attrs.permissions != null) flags = flags or SSH_FILEXFER_ATTR_PERMISSIONS
        if (attrs.atime != null || attrs.mtime != null) flags = flags or SSH_FILEXFER_ATTR_ACMODTIME

        // Calculate size
        var size = 4 // flags
        if (flags and SSH_FILEXFER_ATTR_SIZE != 0) size += 8
        if (flags and SSH_FILEXFER_ATTR_UIDGID != 0) size += 8
        if (flags and SSH_FILEXFER_ATTR_PERMISSIONS != 0) size += 4
        if (flags and SSH_FILEXFER_ATTR_ACMODTIME != 0) size += 8

        val buf = ByteBuffer.allocate(size)
        buf.putInt(flags)
        if (attrs.size != null) buf.putLong(attrs.size)
        if (flags and SSH_FILEXFER_ATTR_UIDGID != 0) {
            buf.putInt(attrs.uid ?: 0)
            buf.putInt(attrs.gid ?: 0)
        }
        if (attrs.permissions != null) buf.putInt(attrs.permissions)
        if (flags and SSH_FILEXFER_ATTR_ACMODTIME != 0) {
            buf.putInt(attrs.atime ?: 0)
            buf.putInt(attrs.mtime ?: 0)
        }

        return buf.array()
    }
}
