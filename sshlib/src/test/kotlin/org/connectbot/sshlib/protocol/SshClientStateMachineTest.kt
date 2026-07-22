/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

package org.connectbot.sshlib.protocol

import kotlinx.coroutines.test.runTest
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SshClientStateMachineTest {
    @Test
    fun `network events cannot bypass authentication guards`() = runTest {
        val callbacks = RecordingCallbacks()
        val machine = SshClientStateMachine(callbacks)

        assertFalse(machine.authenticationSuccess())
        assertFalse(machine.authenticationFailure())
        assertFalse(machine.authorizeAuthenticationPacket())
        assertFalse(machine.authorizeAuthenticatedPacket())
        assertFalse(machine.openChannel("session", 0, 1024, 1024))
        assertFalse("authenticationSuccess" in callbacks.actions)
        assertFalse("sendChannelOpen" in callbacks.actions)
    }

    @Test
    fun `authentication success is an explicit state transition`() = runTest {
        val callbacks = RecordingCallbacks()
        val machine = SshClientStateMachine(callbacks)

        assertTrue(machine.connect())
        assertTrue(machine.receiveVersion(IdBanner()))
        assertTrue(machine.receiveKexInit(SshMsgKexinit()))
        assertTrue(machine.receiveKexDhReply(SshMsgKexdhReply()))
        assertTrue(machine.receiveNewKeys())
        assertTrue(machine.receiveServiceAccept("ssh-userauth"))

        assertFalse(machine.authorizeAuthenticationPacket())
        assertFalse(machine.authorizeAuthenticatedPacket())
        assertFalse(machine.authenticationSuccess())
        assertTrue(machine.beginAuthentication())
        assertTrue(machine.authorizeAuthenticationPacket())
        assertTrue(machine.authenticationSuccess())
        assertFalse(machine.authenticationSuccess())
        assertFalse(machine.authorizeAuthenticationPacket())
        assertTrue(machine.authorizeAuthenticatedPacket())
        assertTrue(machine.openChannel("session", 0, 1024, 1024))
    }

    @Test
    fun `authentication requests cannot overlap without a server response`() = runTest {
        val callbacks = RecordingCallbacks()
        val machine = SshClientStateMachine(callbacks)

        assertTrue(machine.connect())
        assertTrue(machine.receiveVersion(IdBanner()))
        assertTrue(machine.receiveKexInit(SshMsgKexinit()))
        assertTrue(machine.receiveKexDhReply(SshMsgKexdhReply()))
        assertTrue(machine.receiveNewKeys())
        assertTrue(machine.receiveServiceAccept("ssh-userauth"))

        assertTrue(machine.beginAuthentication())
        assertFalse(machine.beginAuthentication())
        assertTrue(machine.authorizeAuthenticationPacket())
        assertTrue(machine.beginAuthentication())
    }

    @Test
    fun `typed rekey guard restores the authenticated state`() = runTest {
        val callbacks = RecordingCallbacks()
        val machine = SshClientStateMachine(callbacks)

        assertTrue(machine.connect())
        assertTrue(machine.receiveVersion(IdBanner()))
        assertTrue(machine.receiveKexInit(SshMsgKexinit()))
        assertTrue(machine.receiveKexEcdhReply(SshMsgKexEcdhReply()))
        assertTrue(machine.receiveNewKeys())
        assertTrue(machine.receiveServiceAccept("ssh-userauth"))
        assertTrue(machine.beginAuthentication())
        assertTrue(machine.authenticationSuccess())

        assertTrue(machine.requestRekey())
        assertTrue(callbacks.rekeying)
        assertTrue(machine.receiveKexInit(SshMsgKexinit()))
        assertTrue(machine.receiveKexEcdhReply(SshMsgKexEcdhReply()))
        assertTrue(machine.receiveNewKeys())

        assertFalse(callbacks.rekeying)
        assertTrue(machine.authorizeAuthenticatedPacket())
    }

    @Test
    fun `a second kex init during key exchange is fatal`() = runTest {
        val callbacks = RecordingCallbacks()
        val machine = SshClientStateMachine(callbacks)

        assertTrue(machine.connect())
        assertTrue(machine.receiveVersion(IdBanner()))
        assertTrue(machine.receiveKexInit(SshMsgKexinit()))
        assertTrue(machine.unexpectedKexInit("duplicate KEXINIT"))

        assertTrue("sendProtocolError:duplicate KEXINIT" in callbacks.actions)
        assertFalse(machine.receiveKexDhReply(SshMsgKexdhReply()))
        assertFalse(machine.receiveKexInit(SshMsgKexinit()))
    }

    @Test
    fun `raw KStateMachine and event hierarchy are private`() {
        val machineField = SshClientStateMachine::class.java.getDeclaredField("stateMachine")
        assertTrue(Modifier.isPrivate(machineField.modifiers))

        val eventClass = SshClientStateMachine::class.java.declaredClasses.single { it.simpleName == "SshEvent" }
        assertTrue(Modifier.isPrivate(eventClass.modifiers))
        val processMethod = SshClientStateMachine::class.java.declaredMethods.single { it.name == "process" }
        assertTrue(Modifier.isPrivate(processMethod.modifiers))
    }

    private class RecordingCallbacks : SshClientCallbacks {
        val actions = mutableListOf<String>()
        var rekeying = false
        var authenticationRequestPending = false

        override fun sendVersion() {
            actions += "sendVersion"
        }
        override fun receiveVersion(banner: IdBanner) {
            actions += "receiveVersion"
        }
        override suspend fun sendKexInit() {
            actions += "sendKexInit"
        }
        override fun receiveKexInit(msg: SshMsgKexinit) {
            actions += "receiveKexInit"
        }
        override suspend fun sendKexExchangeInit() {
            actions += "sendKexExchangeInit"
        }
        override suspend fun receiveKexDhReply(msg: SshMsgKexdhReply) {
            actions += "receiveKexDhReply"
        }
        override suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply) {
            actions += "receiveKexEcdhReply"
        }
        override suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply) {
            actions += "receiveKexDhGexReply"
        }
        override fun isRekeying(): Boolean = rekeying
        override fun isAuthenticationRequestPending(): Boolean = authenticationRequestPending
        override fun authenticationRequestStarted() {
            authenticationRequestPending = true
        }
        override fun authenticationRequestResponseReceived() {
            authenticationRequestPending = false
        }
        override fun rekeyStarted() {
            actions += "rekeyStarted"
            rekeying = true
        }
        override fun rekeyComplete() {
            actions += "rekeyComplete"
            rekeying = false
        }
        override suspend fun sendKexDhGexInit() {
            actions += "sendKexDhGexInit"
        }
        override suspend fun sendNewKeys() {
            actions += "sendNewKeys"
        }
        override fun receiveNewKeys() {
            actions += "receiveNewKeys"
        }
        override fun activateEncryption() {
            actions += "activateEncryption"
        }
        override suspend fun sendClientExtInfo() {
            actions += "sendClientExtInfo"
        }
        override suspend fun sendServiceRequest(service: String) {
            actions += "sendServiceRequest"
        }
        override fun receiveServiceAccept(service: String) {
            actions += "receiveServiceAccept"
        }
        override fun startAuthentication() {
            actions += "startAuthentication"
        }
        override fun authenticationSuccess() {
            actions += "authenticationSuccess"
            authenticationRequestPending = false
        }
        override fun authenticationFailure() {
            actions += "authenticationFailure"
            authenticationRequestPending = false
        }
        override fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest) {
            actions += "receiveUserauthInfoRequest"
        }
        override fun receiveUserauthBanner(msg: SshMsgUserauthBanner) {
            actions += "receiveUserauthBanner"
        }
        override suspend fun sendChannelOpen(
            channelType: String,
            localChannelNumber: Int,
            initialWindowSize: Int,
            maxPacketSize: Int,
        ) {
            actions += "sendChannelOpen"
        }
        override fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation) {
            actions += "receiveChannelOpenConfirmation"
        }
        override fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure) {
            actions += "receiveChannelOpenFailure"
        }
        override suspend fun sendChannelRequest(
            recipientChannel: Int,
            requestType: String,
            wantReply: Boolean,
            message: SshMsgChannelRequest,
        ) {
            actions += "sendChannelRequest"
        }
        override fun receiveChannelSuccess(recipientChannel: Int) {
            actions += "receiveChannelSuccess"
        }
        override fun receiveChannelFailure(recipientChannel: Int) {
            actions += "receiveChannelFailure"
        }
        override suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest) {
            actions += "receiveGlobalRequest"
        }
        override fun debug(msg: SshMsgDebug) {
            actions += "debug"
        }
        override fun ignore() {
            actions += "ignore"
        }
        override suspend fun disconnect() {
            actions += "disconnect"
        }
        override suspend fun sendProtocolError(description: String) {
            actions += "sendProtocolError:$description"
        }
        override fun onStateEnter(stateName: String) = Unit
        override fun onStateExit(stateName: String) = Unit
    }
}
