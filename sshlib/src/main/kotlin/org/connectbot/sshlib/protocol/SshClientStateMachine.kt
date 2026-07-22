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

import ru.nsk.kstatemachine.event.Event
import ru.nsk.kstatemachine.state.HistoryState
import ru.nsk.kstatemachine.state.HistoryType
import ru.nsk.kstatemachine.state.IState
import ru.nsk.kstatemachine.state.State
import ru.nsk.kstatemachine.state.activeStates
import ru.nsk.kstatemachine.state.finalState
import ru.nsk.kstatemachine.state.historyState
import ru.nsk.kstatemachine.state.initialState
import ru.nsk.kstatemachine.state.invoke
import ru.nsk.kstatemachine.state.onEntry
import ru.nsk.kstatemachine.state.onExit
import ru.nsk.kstatemachine.state.state
import ru.nsk.kstatemachine.state.transition
import ru.nsk.kstatemachine.statemachine.ProcessingResult
import ru.nsk.kstatemachine.statemachine.StateMachine
import ru.nsk.kstatemachine.statemachine.createStdLibStateMachine
import ru.nsk.kstatemachine.transition.TransitionParams
import ru.nsk.kstatemachine.transition.onTriggered

/**
 * SSH Client Connection State Machine using KStateMachine.
 *
 * This state machine models the SSH protocol from a client's perspective,
 * managing the connection lifecycle from initial connection through authentication.
 *
 * States represent the SSH client connection lifecycle:
 * - Unconnected: Initial state, not connected
 * - WaitVersion: Waiting for server version/banner
 * - WaitKexInit: Waiting for server's KEX initialization
 * - WaitKex: Waiting for key exchange messages (DH, ECDH, etc.)
 * - WaitKexDhGexInit: Waiting for DH-GEX reply after sending SSH_MSG_KEX_DH_GEX_INIT
 * - WaitNewKeys: Waiting for SSH_MSG_NEWKEYS from server
 * - WaitService: Waiting for service acceptance
 * - PostAuthenticated: Compound state for all post-auth states (Authenticated, ChannelOpen, etc.)
 * - Disconnected: Connection terminated
 *
 * Note: This state machine is designed for SSH clients only. For server-side
 * state management, a separate SshServerStateMachine would be needed.
 */
internal class SshClientStateMachine(
    private val callbacks: SshClientCallbacks,
) {
    private val parsedPacket = setOf(SshEventOrigin.PARSED_PACKET)
    private val localCommand = setOf(SshEventOrigin.LOCAL_COMMAND)
    private val rekeying = SshFormalGuard.Fact(SshBooleanFact.REKEYING)

    private sealed class SshEvent : Event {
        object Connect : SshEvent()
        data class ReceiveVersion(val banner: IdBanner) : SshEvent()
        data class ReceiveKexInit(val msg: SshMsgKexinit) : SshEvent()
        sealed class ReceiveKex : SshEvent() {
            data class DhReply(val msg: SshMsgKexdhReply) : ReceiveKex()
            data class EcdhReply(val msg: SshMsgKexEcdhReply) : ReceiveKex()
            data class DhGexGroup(val msg: SshMsgKexDhGexGroup) : ReceiveKex()
            data class DhGexReply(val msg: SshMsgKexDhGexReply) : ReceiveKex()
        }
        object ReceiveNewKeys : SshEvent()
        data class ReceiveServiceAccept(val service: String) : SshEvent()
        object BeginAuthentication : SshEvent()
        object AuthenticationSuccess : SshEvent()
        object AuthenticationFailure : SshEvent()
        data class ReceiveUserauthInfoRequest(val msg: SshMsgUserauthInfoRequest) : SshEvent()
        data class ReceiveUserauthBanner(val msg: SshMsgUserauthBanner) : SshEvent()
        data class OpenChannel(
            val channelType: String,
            val localChannelNumber: Int,
            val initialWindowSize: Int,
            val maxPacketSize: Int,
        ) : SshEvent()
        data class ReceiveChannelOpenConfirmation(val msg: SshMsgChannelOpenConfirmation) : SshEvent()
        data class ReceiveChannelOpenFailure(val msg: SshMsgChannelOpenFailure) : SshEvent()
        data class SendChannelRequest(
            val recipientChannel: Int,
            val requestType: String,
            val wantReply: Boolean,
            val message: SshMsgChannelRequest,
        ) : SshEvent()
        data class ReceiveChannelSuccess(val recipientChannel: Int) : SshEvent()
        data class ReceiveChannelFailure(val recipientChannel: Int) : SshEvent()
        data class ReceiveGlobalRequest(val msg: SshMsgGlobalRequest) : SshEvent()
        data class ReceiveDebug(val msg: SshMsgDebug) : SshEvent()
        object ReceiveIgnore : SshEvent()
        object AuthorizeAuthenticationPacket : SshEvent()
        object AuthorizeAuthenticatedPacket : SshEvent()
        object AuthorizeConnectionPacket : SshEvent()
        object AuthorizeExtInfo : SshEvent()
        object Disconnect : SshEvent()
        object RekeyStarted : SshEvent()
        data class UnexpectedKexInit(val description: String) : SshEvent()
    }

    private val stateMachine: StateMachine = createStdLibStateMachine {
        val waitVersion = state("WaitVersion")
        val waitKexInit = state("WaitKexInit")
        val waitKex = state("WaitKex")
        val waitKexDhGexInit = state("WaitKexDhGexInit")
        val waitNewKeys = state("WaitNewKeys")
        val waitService = state("WaitService")
        val disconnected = finalState("Disconnected")

        lateinit var postAuthHistory: HistoryState

        val postAuthenticated = state("PostAuthenticated") {
            val authenticationReady = initialState("AuthenticationReady")
            val authenticating = state("Authenticating")
            val authenticated = state("Authenticated")

            authenticationReady {
                onEntry { callbacks.onStateEnter("AuthenticationReady") }
                onExit { callbacks.onStateExit("AuthenticationReady") }

                formalTransition<SshEvent.BeginAuthentication>(
                    id = SshTransitionId.BEGIN_AUTHENTICATION,
                    targetState = authenticating,
                    guard = !SshFormalGuard.Fact(SshBooleanFact.AUTH_REQUEST_PENDING),
                    origins = localCommand,
                    effects = setOf(SshEffect.SEND_USERAUTH_REQUEST),
                ) { callbacks.authenticationRequestStarted() }
                formalTransition<SshEvent.ReceiveUserauthBanner>(
                    id = SshTransitionId.RECEIVE_USERAUTH_BANNER_READY,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_USERAUTH_BANNER),
                ) { callbacks.receiveUserauthBanner(it.event.msg) }
            }

            authenticating {
                onEntry { callbacks.onStateEnter("Authenticating") }
                onExit { callbacks.onStateExit("Authenticating") }

                formalTransition<SshEvent.BeginAuthentication>(
                    id = SshTransitionId.REPEAT_BEGIN_AUTHENTICATION,
                    guard = !SshFormalGuard.Fact(SshBooleanFact.AUTH_REQUEST_PENDING),
                    origins = localCommand,
                    effects = setOf(SshEffect.SEND_USERAUTH_REQUEST),
                ) { callbacks.authenticationRequestStarted() }
                formalTransition<SshEvent.AuthenticationSuccess>(
                    id = SshTransitionId.AUTHENTICATION_SUCCESS,
                    targetState = authenticated,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.AUTHENTICATION_SUCCESS),
                ) { callbacks.authenticationSuccess() }
                formalTransition<SshEvent.AuthenticationFailure>(
                    id = SshTransitionId.AUTHENTICATION_FAILURE,
                    targetState = authenticationReady,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.AUTHENTICATION_FAILURE),
                ) { callbacks.authenticationFailure() }
                formalTransition<SshEvent.ReceiveUserauthInfoRequest>(
                    id = SshTransitionId.RECEIVE_USERAUTH_INFO_REQUEST,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_USERAUTH_INFO_REQUEST),
                ) { callbacks.receiveUserauthInfoRequest(it.event.msg) }
                formalTransition<SshEvent.ReceiveUserauthBanner>(
                    id = SshTransitionId.RECEIVE_USERAUTH_BANNER_AUTHENTICATING,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_USERAUTH_BANNER),
                ) { callbacks.receiveUserauthBanner(it.event.msg) }
                formalTransition<SshEvent.AuthorizeAuthenticationPacket>(
                    id = SshTransitionId.AUTHORIZE_AUTHENTICATION_PACKET,
                    origins = parsedPacket,
                ) { callbacks.authenticationRequestResponseReceived() }
            }

            authenticated {
                onEntry { callbacks.onStateEnter("Authenticated") }
                onExit { callbacks.onStateExit("Authenticated") }

                formalTransition<SshEvent.AuthorizeAuthenticatedPacket>(
                    id = SshTransitionId.AUTHORIZE_AUTHENTICATED_PACKET,
                    origins = parsedPacket,
                )
                formalTransition<SshEvent.ReceiveGlobalRequest>(
                    id = SshTransitionId.RECEIVE_GLOBAL_REQUEST,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_GLOBAL_REQUEST),
                ) { callbacks.receiveGlobalRequest(it.event.msg) }
                formalTransition<SshEvent.OpenChannel>(
                    id = SshTransitionId.OPEN_CHANNEL,
                    origins = localCommand,
                    effects = setOf(SshEffect.SEND_CHANNEL_OPEN),
                ) {
                    callbacks.sendChannelOpen(
                        it.event.channelType,
                        it.event.localChannelNumber,
                        it.event.initialWindowSize,
                        it.event.maxPacketSize,
                    )
                }
                formalTransition<SshEvent.ReceiveChannelOpenConfirmation>(
                    id = SshTransitionId.RECEIVE_CHANNEL_OPEN_CONFIRMATION,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_CHANNEL_OPEN_CONFIRMATION),
                ) { callbacks.receiveChannelOpenConfirmation(it.event.msg) }
                formalTransition<SshEvent.ReceiveChannelOpenFailure>(
                    id = SshTransitionId.RECEIVE_CHANNEL_OPEN_FAILURE,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_CHANNEL_OPEN_FAILURE),
                ) { callbacks.receiveChannelOpenFailure(it.event.msg) }
                formalTransition<SshEvent.SendChannelRequest>(
                    id = SshTransitionId.SEND_CHANNEL_REQUEST,
                    origins = localCommand,
                    effects = setOf(SshEffect.SEND_CHANNEL_REQUEST),
                ) {
                    callbacks.sendChannelRequest(
                        it.event.recipientChannel,
                        it.event.requestType,
                        it.event.wantReply,
                        it.event.message,
                    )
                }
                formalTransition<SshEvent.ReceiveChannelSuccess>(
                    id = SshTransitionId.RECEIVE_CHANNEL_SUCCESS,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_CHANNEL_SUCCESS),
                ) { callbacks.receiveChannelSuccess(it.event.recipientChannel) }
                formalTransition<SshEvent.ReceiveChannelFailure>(
                    id = SshTransitionId.RECEIVE_CHANNEL_FAILURE,
                    origins = parsedPacket,
                    effects = setOf(SshEffect.RECEIVE_CHANNEL_FAILURE),
                ) { callbacks.receiveChannelFailure(it.event.recipientChannel) }
            }

            postAuthHistory = historyState(
                name = "PostAuthHistory",
                defaultState = authenticationReady,
                historyType = HistoryType.DEEP,
            )

            formalTransition<SshEvent.RekeyStarted>(
                id = SshTransitionId.REKEY_STARTED,
                targetState = waitKexInit,
                origins = setOf(SshEventOrigin.LOCAL_COMMAND, SshEventOrigin.PARSED_PACKET, SshEventOrigin.TIMER),
                effects = setOf(SshEffect.REKEY_STARTED, SshEffect.SEND_KEX_INIT),
            ) {
                callbacks.rekeyStarted()
                callbacks.sendKexInit()
            }
            formalTransition<SshEvent.AuthorizeExtInfo>(
                id = SshTransitionId.AUTHORIZE_POST_AUTH_EXT_INFO,
                origins = parsedPacket,
            )
            formalTransition<SshEvent.AuthorizeConnectionPacket>(
                id = SshTransitionId.AUTHORIZE_CONNECTION_PACKET,
                origins = parsedPacket,
            )
        }

        initialState("Unconnected") {
            onEntry { callbacks.onStateEnter("Unconnected") }
            onExit { callbacks.onStateExit("Unconnected") }

            formalTransition<SshEvent.Connect>(
                id = SshTransitionId.CONNECT,
                targetState = waitVersion,
                origins = localCommand,
                effects = setOf(SshEffect.SEND_VERSION),
            ) { callbacks.sendVersion() }
        }

        waitVersion {
            onEntry { callbacks.onStateEnter("WaitVersion") }
            onExit { callbacks.onStateExit("WaitVersion") }

            formalTransition<SshEvent.ReceiveVersion>(
                id = SshTransitionId.RECEIVE_VERSION,
                targetState = waitKexInit,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_VERSION, SshEffect.SEND_KEX_INIT),
            ) {
                callbacks.receiveVersion(it.event.banner)
                callbacks.sendKexInit()
            }
        }

        waitKexInit {
            onEntry { callbacks.onStateEnter("WaitKexInit") }
            onExit { callbacks.onStateExit("WaitKexInit") }

            formalTransition<SshEvent.ReceiveKexInit>(
                id = SshTransitionId.RECEIVE_KEX_INIT,
                targetState = waitKex,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_KEX_INIT, SshEffect.SEND_KEX_EXCHANGE_INIT),
            ) {
                callbacks.receiveKexInit(it.event.msg)
                callbacks.sendKexExchangeInit()
            }
        }

        waitKex {
            onEntry { callbacks.onStateEnter("WaitKex") }
            onExit { callbacks.onStateExit("WaitKex") }

            formalTransition<SshEvent.ReceiveKex.DhReply>(
                id = SshTransitionId.RECEIVE_KEX_DH_REPLY,
                targetState = waitNewKeys,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_KEX_DH_REPLY, SshEffect.SEND_NEW_KEYS),
            ) {
                callbacks.receiveKexDhReply(it.event.msg)
                callbacks.sendNewKeys()
            }
            formalTransition<SshEvent.ReceiveKex.EcdhReply>(
                id = SshTransitionId.RECEIVE_KEX_ECDH_REPLY,
                targetState = waitNewKeys,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_KEX_ECDH_REPLY, SshEffect.SEND_NEW_KEYS),
            ) {
                callbacks.receiveKexEcdhReply(it.event.msg)
                callbacks.sendNewKeys()
            }
            formalTransition<SshEvent.ReceiveKex.DhGexGroup>(
                id = SshTransitionId.RECEIVE_KEX_DH_GEX_GROUP,
                targetState = waitKexDhGexInit,
                origins = parsedPacket,
                effects = setOf(SshEffect.SEND_KEX_DH_GEX_INIT),
            ) { callbacks.sendKexDhGexInit() }
            formalTransition<SshEvent.UnexpectedKexInit>(
                id = SshTransitionId.UNEXPECTED_KEX_INIT_WAIT_KEX,
                targetState = disconnected,
                origins = parsedPacket,
                effects = setOf(SshEffect.SEND_PROTOCOL_ERROR, SshEffect.DISCONNECT),
            ) { callbacks.sendProtocolError(it.event.description) }
        }

        waitKexDhGexInit {
            onEntry { callbacks.onStateEnter("WaitKexDhGexInit") }
            onExit { callbacks.onStateExit("WaitKexDhGexInit") }

            formalTransition<SshEvent.ReceiveKex.DhGexReply>(
                id = SshTransitionId.RECEIVE_KEX_DH_GEX_REPLY,
                targetState = waitNewKeys,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_KEX_DH_GEX_REPLY, SshEffect.SEND_NEW_KEYS),
            ) {
                callbacks.receiveKexDhGexReply(it.event.msg)
                callbacks.sendNewKeys()
            }
            formalTransition<SshEvent.UnexpectedKexInit>(
                id = SshTransitionId.UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT,
                targetState = disconnected,
                origins = parsedPacket,
                effects = setOf(SshEffect.SEND_PROTOCOL_ERROR, SshEffect.DISCONNECT),
            ) { callbacks.sendProtocolError(it.event.description) }
        }

        waitNewKeys {
            onEntry { callbacks.onStateEnter("WaitNewKeys") }
            onExit { callbacks.onStateExit("WaitNewKeys") }

            formalTransition<SshEvent.ReceiveNewKeys>(
                id = SshTransitionId.RECEIVE_INITIAL_NEW_KEYS,
                targetState = waitService,
                guard = !rekeying,
                origins = parsedPacket,
                effects = setOf(
                    SshEffect.RECEIVE_NEW_KEYS,
                    SshEffect.ACTIVATE_ENCRYPTION,
                    SshEffect.SEND_CLIENT_EXT_INFO,
                    SshEffect.SEND_SERVICE_REQUEST,
                ),
            ) {
                callbacks.receiveNewKeys()
                callbacks.activateEncryption()
                callbacks.sendClientExtInfo()
                callbacks.sendServiceRequest("ssh-userauth")
            }
            formalTransition<SshEvent.ReceiveNewKeys>(
                id = SshTransitionId.RECEIVE_REKEY_NEW_KEYS,
                targetState = postAuthHistory,
                guard = rekeying,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_NEW_KEYS, SshEffect.ACTIVATE_ENCRYPTION, SshEffect.REKEY_COMPLETE),
            ) {
                callbacks.receiveNewKeys()
                callbacks.activateEncryption()
                callbacks.rekeyComplete()
            }
            formalTransition<SshEvent.UnexpectedKexInit>(
                id = SshTransitionId.UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS,
                targetState = disconnected,
                origins = parsedPacket,
                effects = setOf(SshEffect.SEND_PROTOCOL_ERROR, SshEffect.DISCONNECT),
            ) { callbacks.sendProtocolError(it.event.description) }
        }

        waitService {
            onEntry { callbacks.onStateEnter("WaitService") }
            onExit { callbacks.onStateExit("WaitService") }

            formalTransition<SshEvent.ReceiveServiceAccept>(
                id = SshTransitionId.RECEIVE_SERVICE_ACCEPT,
                targetState = postAuthenticated,
                origins = parsedPacket,
                effects = setOf(SshEffect.RECEIVE_SERVICE_ACCEPT, SshEffect.START_AUTHENTICATION),
            ) {
                callbacks.receiveServiceAccept(it.event.service)
                callbacks.startAuthentication()
            }
            formalTransition<SshEvent.AuthorizeExtInfo>(
                id = SshTransitionId.AUTHORIZE_SERVICE_EXT_INFO,
                origins = parsedPacket,
            )
        }

        formalTransition<SshEvent.ReceiveDebug>(
            id = SshTransitionId.RECEIVE_DEBUG,
            origins = parsedPacket,
            effects = setOf(SshEffect.DEBUG),
        ) { callbacks.debug(it.event.msg) }
        formalTransition<SshEvent.ReceiveIgnore>(
            id = SshTransitionId.RECEIVE_IGNORE,
            origins = parsedPacket,
            effects = setOf(SshEffect.IGNORE),
        ) { callbacks.ignore() }
        formalTransition<SshEvent.Disconnect>(
            id = SshTransitionId.DISCONNECT,
            targetState = disconnected,
            origins = parsedPacket,
            effects = setOf(SshEffect.DISCONNECT),
        ) { callbacks.disconnect() }
    }

    private inline fun <reified E : SshEvent> IState.formalTransition(
        id: SshTransitionId,
        targetState: State? = null,
        guard: SshFormalGuard = SshFormalGuard.Always,
        origins: Set<SshEventOrigin>,
        effects: Set<SshEffect> = emptySet(),
        noinline action: (suspend (TransitionParams<E>) -> Unit)? = null,
    ) {
        val meta = SshFormalTransitionMeta(
            id = id,
            eventClass = E::class,
            targetStateName = targetState?.name,
            targetIsHistory = targetState is HistoryState,
            guard = guard,
            origins = origins,
            effects = effects,
        )
        val transition = transition<E>(id.name) {
            this.targetState = targetState
            metaInfo = meta
            if (guard != SshFormalGuard.Always) {
                this.guard = { guard.evaluate(callbacks) }
            }
        }
        if (action != null) {
            transition.onTriggered(action)
        }
    }

    suspend fun connect(): Boolean = process(SshEvent.Connect)

    suspend fun receiveVersion(banner: IdBanner): Boolean = process(SshEvent.ReceiveVersion(banner))

    suspend fun receiveKexInit(msg: SshMsgKexinit): Boolean = process(SshEvent.ReceiveKexInit(msg))

    suspend fun receiveKexDhReply(msg: SshMsgKexdhReply): Boolean = process(SshEvent.ReceiveKex.DhReply(msg))

    suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply): Boolean = process(SshEvent.ReceiveKex.EcdhReply(msg))

    suspend fun receiveKexDhGexGroup(msg: SshMsgKexDhGexGroup): Boolean = process(SshEvent.ReceiveKex.DhGexGroup(msg))

    suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply): Boolean = process(SshEvent.ReceiveKex.DhGexReply(msg))

    suspend fun receiveNewKeys(): Boolean = process(SshEvent.ReceiveNewKeys)

    suspend fun receiveServiceAccept(service: String): Boolean = service == "ssh-userauth" && process(SshEvent.ReceiveServiceAccept(service))

    suspend fun beginAuthentication(): Boolean = process(SshEvent.BeginAuthentication)

    suspend fun authenticationSuccess(): Boolean = process(SshEvent.AuthenticationSuccess)

    suspend fun authenticationFailure(): Boolean = process(SshEvent.AuthenticationFailure)

    suspend fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest): Boolean = process(SshEvent.ReceiveUserauthInfoRequest(msg))

    suspend fun receiveUserauthBanner(msg: SshMsgUserauthBanner): Boolean = process(SshEvent.ReceiveUserauthBanner(msg))

    suspend fun openChannel(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int): Boolean = process(SshEvent.OpenChannel(channelType, localChannelNumber, initialWindowSize, maxPacketSize))

    suspend fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation): Boolean = process(SshEvent.ReceiveChannelOpenConfirmation(msg))

    suspend fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure): Boolean = process(SshEvent.ReceiveChannelOpenFailure(msg))

    suspend fun sendChannelRequest(
        recipientChannel: Int,
        requestType: String,
        wantReply: Boolean,
        message: SshMsgChannelRequest,
    ): Boolean = process(SshEvent.SendChannelRequest(recipientChannel, requestType, wantReply, message))

    suspend fun receiveChannelSuccess(recipientChannel: Int): Boolean = process(SshEvent.ReceiveChannelSuccess(recipientChannel))

    suspend fun receiveChannelFailure(recipientChannel: Int): Boolean = process(SshEvent.ReceiveChannelFailure(recipientChannel))

    suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest): Boolean = process(SshEvent.ReceiveGlobalRequest(msg))

    suspend fun receiveDebug(msg: SshMsgDebug): Boolean = process(SshEvent.ReceiveDebug(msg))

    suspend fun receiveIgnore(): Boolean = process(SshEvent.ReceiveIgnore)

    suspend fun authorizeAuthenticationPacket(): Boolean = process(SshEvent.AuthorizeAuthenticationPacket)

    suspend fun authorizeAuthenticatedPacket(): Boolean = process(SshEvent.AuthorizeAuthenticatedPacket)

    suspend fun authorizeConnectionPacket(): Boolean = process(SshEvent.AuthorizeConnectionPacket)

    suspend fun authorizeExtInfo(): Boolean = process(SshEvent.AuthorizeExtInfo)

    suspend fun disconnect(): Boolean = process(SshEvent.Disconnect)

    suspend fun requestRekey(): Boolean = process(SshEvent.RekeyStarted)

    suspend fun unexpectedKexInit(description: String): Boolean = process(SshEvent.UnexpectedKexInit(description))

    fun isPostAuthenticated(): Boolean = stateMachine.activeStates().any { it.name == "PostAuthenticated" }

    fun isKexInProgress(): Boolean = stateMachine.activeStates().any {
        it.name == "WaitKexInit" || it.name == "WaitKex" || it.name == "WaitKexDhGexInit" || it.name == "WaitNewKeys"
    }

    fun isWaitingForKexInit(): Boolean = stateMachine.activeStates().any { it.name == "WaitKexInit" }

    internal fun formalModel(): SshStateMachineFormalModel = stateMachine.toSshFormalModel()

    private suspend fun process(event: SshEvent): Boolean = stateMachine.processEvent(event) == ProcessingResult.PROCESSED
}

internal interface SshClientCallbacks {
    fun sendVersion()
    fun receiveVersion(banner: IdBanner)
    suspend fun sendKexInit()
    fun receiveKexInit(msg: SshMsgKexinit)
    suspend fun sendKexExchangeInit()
    suspend fun receiveKexDhReply(msg: SshMsgKexdhReply)
    suspend fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply)
    suspend fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply)
    fun isRekeying(): Boolean
    fun isAuthenticationRequestPending(): Boolean
    fun authenticationRequestStarted()
    fun authenticationRequestResponseReceived()
    fun rekeyStarted()
    fun rekeyComplete()
    suspend fun sendKexDhGexInit()
    suspend fun sendNewKeys()
    fun receiveNewKeys()
    fun activateEncryption()
    suspend fun sendClientExtInfo()
    suspend fun sendServiceRequest(service: String)
    fun receiveServiceAccept(service: String)
    fun startAuthentication()
    fun authenticationSuccess()
    fun authenticationFailure()
    fun receiveUserauthInfoRequest(msg: SshMsgUserauthInfoRequest)
    fun receiveUserauthBanner(msg: SshMsgUserauthBanner)
    suspend fun sendChannelOpen(channelType: String, localChannelNumber: Int, initialWindowSize: Int, maxPacketSize: Int)
    fun receiveChannelOpenConfirmation(msg: SshMsgChannelOpenConfirmation)
    fun receiveChannelOpenFailure(msg: SshMsgChannelOpenFailure)
    suspend fun sendChannelRequest(recipientChannel: Int, requestType: String, wantReply: Boolean, message: SshMsgChannelRequest)
    fun receiveChannelSuccess(recipientChannel: Int)
    fun receiveChannelFailure(recipientChannel: Int)
    suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest)
    fun debug(msg: SshMsgDebug)
    fun ignore()
    suspend fun disconnect()
    suspend fun sendProtocolError(description: String)
    fun onStateEnter(stateName: String)
    fun onStateExit(stateName: String)
}
