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
    sealed class SshEvent : Event {
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
        object ReceiveChannelSuccess : SshEvent()
        object ReceiveChannelFailure : SshEvent()
        data class ReceiveGlobalRequest(val msg: SshMsgGlobalRequest) : SshEvent()
        data class ReceiveDebug(val msg: SshMsgDebug) : SshEvent()
        object ReceiveIgnore : SshEvent()
        object Disconnect : SshEvent()
        object RekeyStarted : SshEvent()
    }

    val stateMachine: StateMachine = createStdLibStateMachine {
        val waitVersion = state("WaitVersion")
        val waitKexInit = state("WaitKexInit")
        val waitKex = state("WaitKex")
        val waitKexDhGexInit = state("WaitKexDhGexInit")
        val waitNewKeys = state("WaitNewKeys")
        val waitService = state("WaitService")
        val disconnected = finalState("Disconnected")

        lateinit var postAuthHistory: HistoryState

        val postAuthenticated = state("PostAuthenticated") {
            val authenticated = initialState("Authenticated")
            val waitChannelOpenConfirmation = state("WaitChannelOpenConfirmation")
            val channelOpen = state("ChannelOpen")
            val waitChannelRequestReply = state("WaitChannelRequestReply")

            authenticated {
                onEntry { callbacks.onStateEnter("Authenticated") }
                onExit { callbacks.onStateExit("Authenticated") }

                transition<SshEvent.OpenChannel> {
                    targetState = waitChannelOpenConfirmation
                    onTriggered {
                        callbacks.sendChannelOpen(
                            it.event.channelType,
                            it.event.localChannelNumber,
                            it.event.initialWindowSize,
                            it.event.maxPacketSize,
                        )
                    }
                }
            }

            waitChannelOpenConfirmation {
                onEntry { callbacks.onStateEnter("WaitChannelOpenConfirmation") }
                onExit { callbacks.onStateExit("WaitChannelOpenConfirmation") }

                transition<SshEvent.ReceiveChannelOpenConfirmation> {
                    targetState = channelOpen
                    onTriggered { callbacks.receiveChannelOpenConfirmation(it.event.msg) }
                }
                transition<SshEvent.ReceiveChannelOpenFailure> {
                    targetState = authenticated
                    onTriggered { callbacks.receiveChannelOpenFailure(it.event.msg) }
                }
            }

            channelOpen {
                onEntry { callbacks.onStateEnter("ChannelOpen") }
                onExit { callbacks.onStateExit("ChannelOpen") }

                transition<SshEvent.SendChannelRequest> {
                    targetState = waitChannelRequestReply
                    onTriggered {
                        callbacks.sendChannelRequest(
                            it.event.recipientChannel,
                            it.event.requestType,
                            it.event.wantReply,
                            it.event.message,
                        )
                    }
                }
            }

            waitChannelRequestReply {
                onEntry { callbacks.onStateEnter("WaitChannelRequestReply") }
                onExit { callbacks.onStateExit("WaitChannelRequestReply") }

                transition<SshEvent.ReceiveChannelSuccess> {
                    targetState = channelOpen
                    onTriggered { callbacks.receiveChannelSuccess() }
                }
                transition<SshEvent.ReceiveChannelFailure> {
                    targetState = channelOpen
                    onTriggered { callbacks.receiveChannelFailure() }
                }
            }

            postAuthHistory = historyState(
                name = "PostAuthHistory",
                defaultState = authenticated,
                historyType = HistoryType.SHALLOW,
            )

            transition<SshEvent.RekeyStarted> {
                targetState = waitKexInit
                onTriggered {
                    callbacks.rekeyStarted()
                    callbacks.sendKexInit()
                }
            }
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
        }

        transition<SshEvent.AuthenticationSuccess> {
            onTriggered { callbacks.authenticationSuccess() }
        }
        transition<SshEvent.AuthenticationFailure> {
            onTriggered { callbacks.authenticationFailure() }
        }
        transition<SshEvent.ReceiveUserauthInfoRequest> {
            onTriggered { callbacks.receiveUserauthInfoRequest(it.event.msg) }
        }
        transition<SshEvent.ReceiveUserauthBanner> {
            onTriggered { callbacks.receiveUserauthBanner(it.event.msg) }
        }
        transition<SshEvent.ReceiveDebug> {
            onTriggered { callbacks.debug(it.event.msg) }
        }
        transition<SshEvent.ReceiveIgnore> {
            onTriggered { callbacks.ignore() }
        }
        transition<SshEvent.ReceiveGlobalRequest> {
            onTriggered { callbacks.receiveGlobalRequest(it.event.msg) }
        }
        transition<SshEvent.Disconnect> {
            targetState = disconnected
            onTriggered { callbacks.disconnect() }
        }
    }

    suspend fun processEvent(event: SshEvent) {
        stateMachine.processEvent(event)
    }

    val currentState: String
        get() = stateMachine.activeStates().firstOrNull()?.name ?: "Unknown"

    fun isInState(stateName: String): Boolean = stateMachine.activeStates().any { it.name == stateName }
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
    suspend fun activateEncryption()
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
    fun receiveChannelSuccess()
    fun receiveChannelFailure()
    suspend fun receiveGlobalRequest(msg: SshMsgGlobalRequest)
    fun debug(msg: SshMsgDebug)
    fun ignore()
    suspend fun disconnect()
    fun onStateEnter(stateName: String)
    fun onStateExit(stateName: String)
}
