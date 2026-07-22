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

import java.util.concurrent.ConcurrentHashMap

/** Resolves SSH inbound `recipient_channel` values, which are always local channel IDs. */
internal class SshChannelRegistry {
    internal sealed interface Entry {
        val localChannelNumber: Int

        data class Session(
            val channel: SessionChannel,
        ) : Entry {
            override val localChannelNumber = channel.localChannelNumber
        }

        data class Forwarding(
            val channel: ForwardingChannel,
        ) : Entry {
            override val localChannelNumber = channel.localChannelNumber
        }

        data class Agent(
            val channel: AgentChannel,
        ) : Entry {
            override val localChannelNumber = channel.localChannelNumber
        }
    }

    private val entriesByLocalRecipient = ConcurrentHashMap<Int, Entry>()

    fun register(channel: SessionChannel) = register(Entry.Session(channel))

    fun register(channel: ForwardingChannel) = register(Entry.Forwarding(channel))

    fun register(channel: AgentChannel) = register(Entry.Agent(channel))

    fun findByLocalRecipient(localChannelNumber: Int): Entry? = entriesByLocalRecipient[localChannelNumber]

    fun unregister(localChannelNumber: Int) {
        entriesByLocalRecipient.remove(localChannelNumber)
    }

    private fun register(entry: Entry) {
        check(entriesByLocalRecipient.putIfAbsent(entry.localChannelNumber, entry) == null) {
            "Local channel ${entry.localChannelNumber} is already registered"
        }
    }
}
