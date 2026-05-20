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

package org.connectbot.sshlib

/**
 * Opaque file or directory handle returned by SFTP open/opendir operations.
 *
 * Handles are server-assigned and should be closed when no longer needed.
 */
class SftpFileHandle internal constructor(internal val handle: ByteArray) {
    override fun equals(other: Any?): Boolean = other is SftpFileHandle && handle.contentEquals(other.handle)

    override fun hashCode(): Int = handle.contentHashCode()
}

/**
 * File attributes for SFTP operations (SFTPv3 ATTRS structure).
 *
 * All fields are optional — only fields with non-null values are transmitted.
 */
data class SftpAttributes(
    val size: Long? = null,
    val uid: Int? = null,
    val gid: Int? = null,
    val permissions: Int? = null,
    val atime: Int? = null,
    val mtime: Int? = null,
) {
    companion object {
        val EMPTY = SftpAttributes()
    }
}

/**
 * Entry from an SFTP directory listing.
 *
 * @param filename Short filename (e.g. "file.txt")
 * @param longname Long-format listing (e.g. "-rw-r--r-- 1 user group 1234 Jan 1 00:00 file.txt")
 * @param attrs File attributes
 */
data class SftpDirectoryEntry(
    val filename: String,
    val longname: String,
    val attrs: SftpAttributes,
)

/**
 * Flags for SFTP file open operations.
 */
enum class SftpOpenFlag(val value: Int) {
    READ(0x00000001),
    WRITE(0x00000002),
    APPEND(0x00000004),
    CREATE(0x00000008),
    TRUNCATE(0x00000010),
    EXCLUDE(0x00000020),
}

/**
 * SFTP status codes (draft-ietf-secsh-filexfer-02 section 7).
 */
enum class SftpStatusCode(val code: Int) {
    OK(0),
    EOF(1),
    NO_SUCH_FILE(2),
    PERMISSION_DENIED(3),
    FAILURE(4),
    BAD_MESSAGE(5),
    NO_CONNECTION(6),
    CONNECTION_LOST(7),
    OP_UNSUPPORTED(8),
    ;

    companion object {
        fun fromCode(code: Int): SftpStatusCode = entries.firstOrNull { it.code == code } ?: FAILURE
    }
}
