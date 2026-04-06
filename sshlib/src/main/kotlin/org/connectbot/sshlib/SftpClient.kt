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
 * All operations return [SftpResult] instead of throwing exceptions, so errors
 * can be handled structurally. Use [getOrNull] or [getOrThrow] for convenience.
 *
 * Usage:
 * ```kotlin
 * val sftp = client.openSftp() ?: error("Failed to open SFTP")
 * try {
 *     when (val result = sftp.listdir("/home/user")) {
 *         is SftpResult.Success -> result.value.forEach { println(it.filename) }
 *         is SftpResult.ServerError -> println("Error: ${result.message}")
 *         is SftpResult.ProtocolError -> println("Protocol error: ${result.message}")
 *         is SftpResult.IoError -> println("I/O error: ${result.cause}")
 *     }
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

    /** Open a file. Returns a handle for subsequent read/write/close operations. */
    suspend fun open(
        path: String,
        flags: Set<SftpOpenFlag>,
        attrs: SftpAttributes = SftpAttributes.EMPTY,
    ): SftpResult<SftpFileHandle>

    /** Close a file or directory handle. */
    suspend fun close(handle: SftpFileHandle): SftpResult<Unit>

    /**
     * Read data from an open file at the given offset.
     * Returns [SftpResult.Success] with data, or with null at EOF.
     */
    suspend fun read(handle: SftpFileHandle, offset: Long, length: Int): SftpResult<ByteArray?>

    /** Write data to an open file at the given offset. */
    suspend fun write(handle: SftpFileHandle, offset: Long, data: ByteArray): SftpResult<Unit>

    // --- Stat operations ---

    /** Get file attributes, following symlinks. */
    suspend fun stat(path: String): SftpResult<SftpAttributes>

    /** Get file attributes without following symlinks. */
    suspend fun lstat(path: String): SftpResult<SftpAttributes>

    /** Get attributes of an open file handle. */
    suspend fun fstat(handle: SftpFileHandle): SftpResult<SftpAttributes>

    /** Set file attributes by path. */
    suspend fun setstat(path: String, attrs: SftpAttributes): SftpResult<Unit>

    /** Set attributes of an open file handle. */
    suspend fun fsetstat(handle: SftpFileHandle, attrs: SftpAttributes): SftpResult<Unit>

    // --- Directory operations ---

    /** Open a directory for reading. */
    suspend fun opendir(path: String): SftpResult<SftpFileHandle>

    /**
     * Read the next batch of directory entries.
     * Returns [SftpResult.Success] with entries, or with null at end of directory.
     */
    suspend fun readdir(handle: SftpFileHandle): SftpResult<List<SftpDirectoryEntry>?>

    /**
     * List all entries in a directory. Convenience method that handles
     * opendir/readdir/close internally.
     */
    suspend fun listdir(path: String): SftpResult<List<SftpDirectoryEntry>> {
        val handleResult = opendir(path)
        val handle = when (handleResult) {
            is SftpResult.Success -> handleResult.value
            is SftpResult.ServerError -> return handleResult
            is SftpResult.ProtocolError -> return handleResult
            is SftpResult.IoError -> return handleResult
        }
        try {
            val entries = mutableListOf<SftpDirectoryEntry>()
            while (true) {
                when (val batch = readdir(handle)) {
                    is SftpResult.Success -> {
                        if (batch.value == null) break
                        entries.addAll(batch.value)
                    }

                    is SftpResult.ServerError -> return batch

                    is SftpResult.ProtocolError -> return batch

                    is SftpResult.IoError -> return batch
                }
            }
            return SftpResult.Success(entries)
        } finally {
            close(handle)
        }
    }

    /** Create a directory. */
    suspend fun mkdir(path: String, attrs: SftpAttributes = SftpAttributes.EMPTY): SftpResult<Unit>

    /** Remove an empty directory. */
    suspend fun rmdir(path: String): SftpResult<Unit>

    // --- File management ---

    /** Delete a file. */
    suspend fun remove(path: String): SftpResult<Unit>

    /** Rename or move a file. */
    suspend fun rename(oldPath: String, newPath: String): SftpResult<Unit>

    // --- Path operations ---

    /** Resolve a path to its canonical absolute form. */
    suspend fun realpath(path: String): SftpResult<String>

    /** Read the target of a symbolic link. */
    suspend fun readlink(path: String): SftpResult<String>

    /** Create a symbolic link. */
    suspend fun symlink(targetPath: String, linkPath: String): SftpResult<Unit>

    /** Close this SFTP session and the underlying SSH channel. */
    override fun close()
}
