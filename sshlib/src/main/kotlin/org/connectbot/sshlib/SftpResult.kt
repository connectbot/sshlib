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
 * Result type for SFTP operations. Replaces thrown exceptions with a
 * sealed interface so callers can handle errors structurally.
 */
sealed interface SftpResult<out T> {
    /** Operation succeeded with [value]. */
    data class Success<T>(val value: T) : SftpResult<T>

    /** SFTP server returned an error status. */
    data class ServerError(
        val statusCode: SftpStatusCode,
        val message: String,
    ) : SftpResult<Nothing>

    /** SFTP protocol violation (unexpected packet type, malformed data). */
    data class ProtocolError(val message: String) : SftpResult<Nothing>

    /** Network or I/O error. */
    data class IoError(val cause: Throwable) : SftpResult<Nothing>
}

/** Convenience: extract value or null for success, throws nothing. */
fun <T> SftpResult<T>.getOrNull(): T? = when (this) {
    is SftpResult.Success -> value
    else -> null
}

/** Convenience: extract value or throw for interop with blocking APIs. */
fun <T> SftpResult<T>.getOrThrow(): T = when (this) {
    is SftpResult.Success -> value
    is SftpResult.ServerError -> throw SftpException(statusCode, message)
    is SftpResult.ProtocolError -> throw SftpException(SftpStatusCode.BAD_MESSAGE, message)
    is SftpResult.IoError -> throw SftpException(SftpStatusCode.FAILURE, cause.message ?: "I/O error", cause)
}
