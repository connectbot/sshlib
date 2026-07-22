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

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.protocol.SshChannelState
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SshChannelRegistryTest {
    @Test
    fun `local and remote recipients resolve one established channel`() {
        val registry = SshChannelRegistry()
        val session = sessionChannel(local = 7, remote = 70)

        registry.register(session)

        assertIs<SshChannelRegistry.Entry.Established.Session>(registry.findByLocalRecipient(7))
        assertSame(
            session,
            registry.findByRemoteRecipient(70)?.let {
                (it as SshChannelRegistry.Entry.Established.Session).channel
            },
        )
        assertNull(registry.findByLocalRecipient(8))
        assertNull(registry.findByRemoteRecipient(71))
    }

    @Test
    fun `duplicate local recipient is rejected across channel kinds`() {
        val registry = SshChannelRegistry()
        registry.register(sessionChannel(local = 7, remote = 70))

        assertFailsWith<IllegalStateException> {
            registry.register(forwardingChannel(local = 7, remote = 80))
        }
    }

    @Test
    fun `duplicate remote recipient is rejected across local IDs`() {
        val registry = SshChannelRegistry()
        registry.register(sessionChannel(local = 7, remote = 70))

        assertFailsWith<IllegalStateException> {
            registry.register(forwardingChannel(local = 8, remote = 70))
        }
    }

    @Test
    fun `pending open continuously owns local ID through atomic promotion`() {
        val registry = SshChannelRegistry()
        val deferred = CompletableDeferred<org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation?>()
        val lifecycle = SshChannelStateMachine(SshChannelState.OPENING)
        registry.registerPendingSession(7, deferred, lifecycle)
        val pending = registry.findPendingSession(7)!!

        registry.bindRemoteRecipient(pending, 70)
        val session = sessionChannel(local = 7, remote = 70)
        registry.promote(pending, session)

        assertNull(registry.findPendingSession(7))
        assertSame(
            session,
            (registry.findByLocalRecipient(7) as SshChannelRegistry.Entry.Established.Session).channel,
        )
        assertEquals(7, registry.findByRemoteRecipient(70)?.localChannelNumber)
    }

    @Test
    fun `unregister removes local and remote indexes together`() {
        val registry = SshChannelRegistry()
        registry.register(sessionChannel(local = 7, remote = 70))

        registry.unregister(7)

        assertNull(registry.findByLocalRecipient(7))
        assertNull(registry.findByRemoteRecipient(70))
    }

    @Test
    fun `disconnect cascade removes and closes pending and established entries`() = runTest {
        val registry = SshChannelRegistry()
        val session = sessionChannel(local = 7, remote = 70)
        coEvery { session.onDisconnected() } returns Unit
        val pendingDeferred = CompletableDeferred<ForwardingChannel?>()
        registry.register(session)
        registry.registerPendingForwarding(
            localChannelNumber = 8,
            deferred = pendingDeferred,
            maxPacketSize = 32 * 1024,
            initialWindowSize = 64 * 1024,
            lifecycle = SshChannelStateMachine(SshChannelState.OPENING),
        )
        val cause = IllegalStateException("connection lost")

        registry.disconnectAll(cause)

        coVerify(exactly = 1) { session.onDisconnected() }
        assertTrue(registry.snapshot().isEmpty())
        assertNull(registry.findByRemoteRecipient(70))
        assertEquals(cause.message, assertFailsWith<IllegalStateException> { pendingDeferred.await() }.message)
        assertFailsWith<IllegalStateException> {
            registry.register(sessionChannel(local = 9, remote = 90))
        }
    }

    private fun sessionChannel(local: Int, remote: Int) = mockk<SessionChannel> {
        every { localChannelNumber } returns local
        every { remoteChannelNumber } returns remote
        every { isOpen } returns true
    }

    private fun forwardingChannel(local: Int, remote: Int) = mockk<ForwardingChannel> {
        every { localChannelNumber } returns local
        every { remoteChannelNumber } returns remote
        every { isOpen } returns true
    }
}
