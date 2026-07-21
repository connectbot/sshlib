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

                transition<SshEvent.BeginAuthentication> {
                    targetState = authenticating
                }
                transition<SshEvent.ReceiveUserauthBanner> {
                    onTriggered { callbacks.receiveUserauthBanner(it.event.msg) }
                }
            }

            authenticating {
                onEntry { callbacks.onStateEnter("Authenticating") }
                onExit { callbacks.onStateExit("Authenticating") }

                transition<SshEvent.BeginAuthentication> {}
                transition<SshEvent.AuthenticationSuccess> {
                    targetState = authenticated
                    onTriggered { callbacks.authenticationSuccess() }
                }
                transition<SshEvent.AuthenticationFailure> {
                    targetState = authenticationReady
                    onTriggered { callbacks.authenticationFailure() }
                }
                transition<SshEvent.ReceiveUserauthInfoRequest> {
                    onTriggered { callbacks.receiveUserauthInfoRequest(it.event.msg) }
                }
                transition<SshEvent.ReceiveUserauthBanner> {
                    onTriggered { callbacks.receiveUserauthBanner(it.event.msg) }
                }
                transition<SshEvent.AuthorizeAuthenticationPacket> {}
            }

            authenticated {
                onEntry { callbacks.onStateEnter("Authenticated") }
                onExit { callbacks.onStateExit("Authenticated") }

                transition<SshEvent.AuthorizeAuthenticatedPacket> {}
                transition<SshEvent.ReceiveGlobalRequest> {
                    onTriggered { callbacks.receiveGlobalRequest(it.event.msg) }
                }
                transition<SshEvent.OpenChannel> {
                    onTriggered {
                        callbacks.sendChannelOpen(
                            it.event.channelType,
                            it.event.localChannelNumber,
                            it.event.initialWindowSize,
                            it.event.maxPacketSize,
                        )
                    }
                }
                transition<SshEvent.ReceiveChannelOpenConfirmation> {
                    onTriggered { callbacks.receiveChannelOpenConfirmation(it.event.msg) }
                }
                transition<SshEvent.ReceiveChannelOpenFailure> {
                    onTriggered { callbacks.receiveChannelOpenFailure(it.event.msg) }
                }
                transition<SshEvent.SendChannelRequest> {
                    onTriggered {
                        callbacks.sendChannelRequest(
                            it.event.recipientChannel,
                            it.event.requestType,
                            it.event.wantReply,
                            it.event.message,
                        )
                    }
                }
                transition<SshEvent.ReceiveChannelSuccess> {
                    onTriggered { callbacks.receiveChannelSuccess(it.event.recipientChannel) }
                }
                transition<SshEvent.ReceiveChannelFailure> {
                    onTriggered { callbacks.receiveChannelFailure(it.event.recipientChannel) }
                }
            }

            postAuthHistory = historyState(
                name = "PostAuthHistory",
                defaultState = authenticationReady,
                historyType = HistoryType.DEEP,
            )

            transition<SshEvent.RekeyStarted> {
                targetState = waitKexInit
                onTriggered {
                    callbacks.rekeyStarted()
                    callbacks.sendKexInit()
                }
            }
            transition<SshEvent.AuthorizeExtInfo> {}
            transition<SshEvent.AuthorizeConnectionPacket> {}
        }

        initialState("Unconnected") {
            onEntry { callbacks.onStateEnter("Unconnected") }
            onExit { callbacks.onStateExit("Unconnected") }

            transition<SshEvent.Connect> {
                targetState = waitVersion
                onTriggered { callbacks.sendVersion() }
            }
        }

        waitVersion {
            onEntry { callbacks.onStateEnter("WaitVersion") }
            onExit { callbacks.onStateExit("WaitVersion") }

            transition<SshEvent.ReceiveVersion> {
                targetState = waitKexInit
                onTriggered {
                    callbacks.receiveVersion(it.event.banner)
                    callbacks.sendKexInit()
                }
            }
        }

        waitKexInit {
            onEntry { callbacks.onStateEnter("WaitKexInit") }
            onExit { callbacks.onStateExit("WaitKexInit") }

            transition<SshEvent.ReceiveKexInit> {
                targetState = waitKex
                onTriggered {
                    callbacks.receiveKexInit(it.event.msg)
                    callbacks.sendKexExchangeInit()
                }
            }
        }

        waitKex {
            onEntry { callbacks.onStateEnter("WaitKex") }
            onExit { callbacks.onStateExit("WaitKex") }

            transition<SshEvent.ReceiveKex.DhReply> {
                targetState = waitNewKeys
                onTriggered {
                    callbacks.receiveKexDhReply(it.event.msg)
                    callbacks.sendNewKeys()
                }
            }
            transition<SshEvent.ReceiveKex.EcdhReply> {
                targetState = waitNewKeys
                onTriggered {
                    callbacks.receiveKexEcdhReply(it.event.msg)
                    callbacks.sendNewKeys()
                }
            }
            transition<SshEvent.ReceiveKex.DhGexGroup> {
                targetState = waitKexDhGexInit
                onTriggered { callbacks.sendKexDhGexInit() }
            }
        }

        waitKexDhGexInit {
            onEntry { callbacks.onStateEnter("WaitKexDhGexInit") }
            onExit { callbacks.onStateExit("WaitKexDhGexInit") }

            transition<SshEvent.ReceiveKex.DhGexReply> {
                targetState = waitNewKeys
                onTriggered {
                    callbacks.receiveKexDhGexReply(it.event.msg)
                    callbacks.sendNewKeys()
                }
            }
        }

        waitNewKeys {
            onEntry { callbacks.onStateEnter("WaitNewKeys") }
            onExit { callbacks.onStateExit("WaitNewKeys") }

            transition<SshEvent.ReceiveNewKeys> {
                guard = { !callbacks.isRekeying() }
                targetState = waitService
                onTriggered {
                    callbacks.receiveNewKeys()
                    callbacks.activateEncryption()
                    callbacks.sendClientExtInfo()
                    callbacks.sendServiceRequest("ssh-userauth")
                }
            }
            transition<SshEvent.ReceiveNewKeys> {
                guard = { callbacks.isRekeying() }
                targetState = postAuthHistory
                onTriggered {
                    callbacks.receiveNewKeys()
                    callbacks.activateEncryption()
                    callbacks.rekeyComplete()
                }
            }
        }

        waitService {
            onEntry { callbacks.onStateEnter("WaitService") }
            onExit { callbacks.onStateExit("WaitService") }

            transition<SshEvent.ReceiveServiceAccept> {
                targetState = postAuthenticated
                onTriggered {
                    callbacks.receiveServiceAccept(it.event.service)
                    callbacks.startAuthentication()
                }
            }
            transition<SshEvent.AuthorizeExtInfo> {}
        }

        transition<SshEvent.ReceiveDebug> {
            onTriggered { callbacks.debug(it.event.msg) }
        }
        transition<SshEvent.ReceiveIgnore> {
            onTriggered { callbacks.ignore() }
        }
        transition<SshEvent.Disconnect> {
            targetState = disconnected
            onTriggered { callbacks.disconnect() }
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

    fun isPostAuthenticated(): Boolean = stateMachine.activeStates().any { it.name == "PostAuthenticated" }

    fun isKexInProgress(): Boolean = stateMachine.activeStates().any {
        it.name == "WaitKexInit" || it.name == "WaitKex" || it.name == "WaitKexDhGexInit" || it.name == "WaitNewKeys"
    }

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
    fun onStateEnter(stateName: String)
    fun onStateExit(stateName: String)
}
