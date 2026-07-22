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

import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class SshChannelRegistryTest {
    @Test
    fun `local recipient resolves exactly one channel kind`() {
        val registry = SshChannelRegistry()
        val session = mockk<SessionChannel> {
            every { localChannelNumber } returns 7
        }

        registry.register(session)

        assertIs<SshChannelRegistry.Entry.Session>(registry.findByLocalRecipient(7))
        assertNull(registry.findByLocalRecipient(8))
    }

    @Test
    fun `duplicate local recipient is rejected across channel kinds`() {
        val registry = SshChannelRegistry()
        val session = mockk<SessionChannel> {
            every { localChannelNumber } returns 7
        }
        val forwarding = mockk<ForwardingChannel> {
            every { localChannelNumber } returns 7
        }
        registry.register(session)

        assertFailsWith<IllegalStateException> {
            registry.register(forwarding)
        }
    }

    @Test
    fun `unregister removes local recipient`() {
        val registry = SshChannelRegistry()
        val agent = mockk<AgentChannel> {
            every { localChannelNumber } returns 7
        }
        registry.register(agent)

        registry.unregister(7)

        assertNull(registry.findByLocalRecipient(7))
    }
}
