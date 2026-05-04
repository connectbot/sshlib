package org.connectbot.sshlib

/**
 * Result of a [SshClient.ping] call.
 */
sealed class PingResult {
    /** The server replied; [elapsedNs] is the round-trip time in nanoseconds. */
    data class Success(val elapsedNs: Long) : PingResult()

    /** The server did not advertise ping support via SSH2_MSG_EXT_INFO. */
    data object NotSupported : PingResult()

    /** There is no active authenticated connection. */
    data object NotAuthenticated : PingResult()

    /** An error occurred while sending the ping or waiting for the reply. */
    data class Failure(val cause: Throwable) : PingResult()
}
