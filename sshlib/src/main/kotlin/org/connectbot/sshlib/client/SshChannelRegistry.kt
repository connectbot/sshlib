/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

package org.connectbot.sshlib.client

import kotlinx.coroutines.CompletableDeferred
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation

/**
 * Authoritative owner of allocated SSH channel IDs and channel lifecycle objects.
 *
 * Inbound `recipient_channel` values use [findByLocalRecipient]. Outbound recipient values use the
 * peer's namespace and can be resolved with [findByRemoteRecipient]. Local and remote indexes are
 * changed together under one lock; callers must never maintain a second authoritative ID map.
 */
internal class SshChannelRegistry {
    internal enum class Kind {
        SESSION,
        FORWARDING,
        AGENT,
    }

    internal sealed interface Entry {
        val localChannelNumber: Int
        val remoteChannelNumber: Int?
        val kind: Kind

        sealed interface Pending : Entry {
            val lifecycle: SshChannelStateMachine
            override var remoteChannelNumber: Int?

            data class Session(
                override val localChannelNumber: Int,
                val deferred: CompletableDeferred<SshMsgChannelOpenConfirmation?>,
                override val lifecycle: SshChannelStateMachine,
                override var remoteChannelNumber: Int? = null,
            ) : Pending {
                override val kind = Kind.SESSION
            }

            data class Forwarding(
                override val localChannelNumber: Int,
                val deferred: CompletableDeferred<ForwardingChannel?>,
                val maxPacketSize: Int,
                val initialWindowSize: Int,
                override val lifecycle: SshChannelStateMachine,
                override var remoteChannelNumber: Int? = null,
            ) : Pending {
                override val kind = Kind.FORWARDING
            }
        }

        sealed interface Established : Entry {
            override val remoteChannelNumber: Int
            val isOpen: Boolean

            suspend fun disconnect()

            data class Session(
                val channel: SessionChannel,
            ) : Established {
                override val localChannelNumber = channel.localChannelNumber
                override val remoteChannelNumber = channel.remoteChannelNumber
                override val kind = Kind.SESSION
                override val isOpen get() = channel.isOpen
                override suspend fun disconnect() = channel.onDisconnected()
            }

            data class Forwarding(
                val channel: ForwardingChannel,
            ) : Established {
                override val localChannelNumber = channel.localChannelNumber
                override val remoteChannelNumber = channel.remoteChannelNumber
                override val kind = Kind.FORWARDING
                override val isOpen get() = channel.isOpen
                override suspend fun disconnect() = channel.onDisconnected()
            }

            data class Agent(
                val channel: AgentChannel,
            ) : Established {
                override val localChannelNumber = channel.localChannelNumber
                override val remoteChannelNumber = channel.remoteChannelNumber
                override val kind = Kind.AGENT
                override val isOpen get() = channel.isOpen
                override suspend fun disconnect() = channel.onDisconnected()
            }
        }
    }

    private val lock = Any()
    private val entriesByLocalRecipient = HashMap<Int, Entry>()
    private val localRecipientByRemoteRecipient = HashMap<Int, Int>()
    private var disconnected = false

    fun registerPendingSession(
        localChannelNumber: Int,
        deferred: CompletableDeferred<SshMsgChannelOpenConfirmation?>,
        lifecycle: SshChannelStateMachine,
    ) = register(Entry.Pending.Session(localChannelNumber, deferred, lifecycle))

    fun registerPendingForwarding(
        localChannelNumber: Int,
        deferred: CompletableDeferred<ForwardingChannel?>,
        maxPacketSize: Int,
        initialWindowSize: Int,
        lifecycle: SshChannelStateMachine,
    ) = register(Entry.Pending.Forwarding(localChannelNumber, deferred, maxPacketSize, initialWindowSize, lifecycle))

    fun register(channel: SessionChannel) = register(Entry.Established.Session(channel))

    fun register(channel: ForwardingChannel) = register(Entry.Established.Forwarding(channel))

    fun register(channel: AgentChannel) = register(Entry.Established.Agent(channel))

    fun findByLocalRecipient(localChannelNumber: Int): Entry.Established? = synchronized(lock) {
        entriesByLocalRecipient[localChannelNumber] as? Entry.Established
    }

    fun findByRemoteRecipient(remoteChannelNumber: Int): Entry.Established? = synchronized(lock) {
        localRecipientByRemoteRecipient[remoteChannelNumber]
            ?.let(entriesByLocalRecipient::get) as? Entry.Established
    }

    fun findPendingSession(localChannelNumber: Int): Entry.Pending.Session? = synchronized(lock) {
        entriesByLocalRecipient[localChannelNumber] as? Entry.Pending.Session
    }

    fun findPendingForwarding(localChannelNumber: Int): Entry.Pending.Forwarding? = synchronized(lock) {
        entriesByLocalRecipient[localChannelNumber] as? Entry.Pending.Forwarding
    }

    fun bindRemoteRecipient(entry: Entry.Pending, remoteChannelNumber: Int) = synchronized(lock) {
        check(!disconnected) { "Channel registry is disconnected" }
        check(entriesByLocalRecipient[entry.localChannelNumber] === entry) {
            "Pending local channel ${entry.localChannelNumber} is no longer registered"
        }
        check(entry.remoteChannelNumber == null) {
            "Pending local channel ${entry.localChannelNumber} already has a remote channel"
        }
        check(localRecipientByRemoteRecipient[remoteChannelNumber] == null) {
            "Remote channel $remoteChannelNumber is already registered"
        }
        entry.remoteChannelNumber = remoteChannelNumber
        localRecipientByRemoteRecipient[remoteChannelNumber] = entry.localChannelNumber
    }

    fun promote(entry: Entry.Pending.Session, channel: SessionChannel) = promote(entry, Entry.Established.Session(channel))

    fun promote(entry: Entry.Pending.Forwarding, channel: ForwardingChannel) = promote(entry, Entry.Established.Forwarding(channel))

    fun removePendingSessionIf(
        localChannelNumber: Int,
        deferred: CompletableDeferred<SshMsgChannelOpenConfirmation?>,
    ): Entry.Pending.Session? = synchronized(lock) {
        val pending = entriesByLocalRecipient[localChannelNumber] as? Entry.Pending.Session
        if (pending?.deferred !== deferred) return@synchronized null
        removeLocked(pending)
        pending
    }

    fun removePendingForwardingIf(
        localChannelNumber: Int,
        deferred: CompletableDeferred<ForwardingChannel?>,
    ): Entry.Pending.Forwarding? = synchronized(lock) {
        val pending = entriesByLocalRecipient[localChannelNumber] as? Entry.Pending.Forwarding
        if (pending?.deferred !== deferred) return@synchronized null
        removeLocked(pending)
        pending
    }

    fun unregister(localChannelNumber: Int): Entry? = synchronized(lock) {
        val removed = entriesByLocalRecipient[localChannelNumber] ?: return@synchronized null
        removeLocked(removed)
        removed
    }

    fun snapshot(): List<Entry> = synchronized(lock) { entriesByLocalRecipient.values.toList() }

    fun establishedSnapshot(): List<Entry.Established> = synchronized(lock) {
        entriesByLocalRecipient.values.filterIsInstance<Entry.Established>()
    }

    /** Atomically removes every entry, then tears each lifecycle down exactly once. */
    suspend fun disconnectAll(cause: Throwable) {
        val entries = synchronized(lock) {
            disconnected = true
            val snapshot = entriesByLocalRecipient.values.toList()
            entriesByLocalRecipient.clear()
            localRecipientByRemoteRecipient.clear()
            snapshot
        }
        entries.forEach { entry ->
            try {
                when (entry) {
                    is Entry.Pending.Session -> entry.lifecycle.disconnect {
                        entry.deferred.completeExceptionally(cause)
                    }

                    is Entry.Pending.Forwarding -> entry.lifecycle.disconnect {
                        entry.deferred.completeExceptionally(cause)
                    }

                    is Entry.Established -> entry.disconnect()
                }
            } catch (cleanupFailure: Throwable) {
                cause.addSuppressed(cleanupFailure)
            }
        }
    }

    private fun promote(pending: Entry.Pending, established: Entry.Established) = synchronized(lock) {
        check(!disconnected) { "Channel registry is disconnected" }
        check(entriesByLocalRecipient[pending.localChannelNumber] === pending) {
            "Pending local channel ${pending.localChannelNumber} is no longer registered"
        }
        check(established.localChannelNumber == pending.localChannelNumber)
        check(established.kind == pending.kind)
        check(established.remoteChannelNumber == pending.remoteChannelNumber) {
            "Remote channel changed while promoting local channel ${pending.localChannelNumber}"
        }
        entriesByLocalRecipient[pending.localChannelNumber] = established
    }

    private fun register(entry: Entry) = synchronized(lock) {
        check(!disconnected) { "Channel registry is disconnected" }
        check(entriesByLocalRecipient[entry.localChannelNumber] == null) {
            "Local channel ${entry.localChannelNumber} is already registered"
        }
        entry.remoteChannelNumber?.let { remoteChannelNumber ->
            check(localRecipientByRemoteRecipient[remoteChannelNumber] == null) {
                "Remote channel $remoteChannelNumber is already registered"
            }
        }
        entriesByLocalRecipient[entry.localChannelNumber] = entry
        entry.remoteChannelNumber?.let { remoteChannelNumber ->
            localRecipientByRemoteRecipient[remoteChannelNumber] = entry.localChannelNumber
        }
    }

    private fun removeLocked(entry: Entry) {
        check(entriesByLocalRecipient.remove(entry.localChannelNumber) === entry)
        entry.remoteChannelNumber?.let { remoteChannelNumber ->
            check(localRecipientByRemoteRecipient.remove(remoteChannelNumber) == entry.localChannelNumber) {
                "Remote channel index is inconsistent for local channel ${entry.localChannelNumber}"
            }
        }
    }
}
