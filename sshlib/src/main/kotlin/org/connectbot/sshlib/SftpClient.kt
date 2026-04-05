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

package org.connectbot.sshlib

/**
 * SFTP client for file transfer over SSH (draft-ietf-secsh-filexfer).
 *
 * Obtain an instance via [SshClient.openSftp]. All methods are suspend functions
 * for use with Kotlin coroutines. Multiple concurrent operations are supported
 * via SFTP request pipelining.
 *
 * Usage:
 * ```kotlin
 * val sftp = client.openSftp() ?: error("Failed to open SFTP")
 * try {
 *     val entries = sftp.listdir("/home/user")
 *     entries.forEach { println(it.filename) }
 * } finally {
 *     sftp.close()
 * }
 * ```
 */
interface SftpClient : AutoCloseable {
    /** The negotiated SFTP protocol version (typically 3). */
    val protocolVersion: Int

    /** Whether this SFTP session is still open. */
    val isOpen: Boolean

    // --- File I/O ---

    /**
     * Open a file. Returns a handle for subsequent read/write/close operations.
     *
     * @throws SftpException on server error (e.g. NO_SUCH_FILE, PERMISSION_DENIED)
     */
    suspend fun open(
        path: String,
        flags: Set<SftpOpenFlag>,
        attrs: SftpAttributes = SftpAttributes.EMPTY,
    ): SftpFileHandle

    /** Close a file or directory handle. */
    suspend fun close(handle: SftpFileHandle)

    /**
     * Read data from an open file at the given offset.
     *
     * @return File data, or null if at EOF
     */
    suspend fun read(handle: SftpFileHandle, offset: Long, length: Int): ByteArray?

    /** Write data to an open file at the given offset. */
    suspend fun write(handle: SftpFileHandle, offset: Long, data: ByteArray)

    // --- Stat operations ---

    /** Get file attributes, following symlinks. */
    suspend fun stat(path: String): SftpAttributes

    /** Get file attributes without following symlinks. */
    suspend fun lstat(path: String): SftpAttributes

    /** Get attributes of an open file handle. */
    suspend fun fstat(handle: SftpFileHandle): SftpAttributes

    /** Set file attributes by path. */
    suspend fun setstat(path: String, attrs: SftpAttributes)

    /** Set attributes of an open file handle. */
    suspend fun fsetstat(handle: SftpFileHandle, attrs: SftpAttributes)

    // --- Directory operations ---

    /** Open a directory for reading. */
    suspend fun opendir(path: String): SftpFileHandle

    /**
     * Read the next batch of directory entries.
     *
     * @return List of entries, or null if end of directory reached
     */
    suspend fun readdir(handle: SftpFileHandle): List<SftpDirectoryEntry>?

    /**
     * List all entries in a directory. Convenience method that handles
     * opendir/readdir/close internally.
     */
    suspend fun listdir(path: String): List<SftpDirectoryEntry> {
        val handle = opendir(path)
        try {
            val entries = mutableListOf<SftpDirectoryEntry>()
            while (true) {
                val batch = readdir(handle) ?: break
                entries.addAll(batch)
            }
            return entries
        } finally {
            close(handle)
        }
    }

    /** Create a directory. */
    suspend fun mkdir(path: String, attrs: SftpAttributes = SftpAttributes.EMPTY)

    /** Remove an empty directory. */
    suspend fun rmdir(path: String)

    // --- File management ---

    /** Delete a file. */
    suspend fun remove(path: String)

    /** Rename or move a file. */
    suspend fun rename(oldPath: String, newPath: String)

    // --- Path operations ---

    /** Resolve a path to its canonical absolute form. */
    suspend fun realpath(path: String): String

    /** Read the target of a symbolic link. */
    suspend fun readlink(path: String): String

    /** Create a symbolic link. */
    suspend fun symlink(targetPath: String, linkPath: String)

    /** Close this SFTP session and the underlying SSH channel. */
    override fun close()
}
