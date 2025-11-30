/*
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

package org.connectbot.sshlib.struct

import ru.nsk.kstatemachine.event.Event
import ru.nsk.kstatemachine.state.*
import ru.nsk.kstatemachine.statemachine.StateMachine
import ru.nsk.kstatemachine.statemachine.createStdLibStateMachine
import ru.nsk.kstatemachine.statemachine.processEventBlocking
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
 * - WaitNewKeys: Waiting for SSH_MSG_NEWKEYS from server
 * - WaitService: Waiting for service acceptance
 * - WaitAuthentication: Waiting for authentication success
 * - Connected: Fully authenticated and connected
 * - Disconnected: Connection terminated
 *
 * Note: This state machine is designed for SSH clients only. For server-side
 * state management, a separate SshServerStateMachine would be needed.
 */
class SshClientStateMachine(
    private val callbacks: SshClientCallbacks
) {
    sealed class SshEvent : Event {
        object Connect : SshEvent()
        data class ReceiveVersion(val banner: IdBanner) : SshEvent()
        data class ReceiveKexInit(val msg: SshMsgKexinit) : SshEvent()
        sealed class ReceiveKex : SshEvent() {
            data class DhReply(val msg: SshMsgKexdhReply) : ReceiveKex()
            data class EcdhReply(val msg: SshMsgKexEcdhReply) : ReceiveKex()
            data class DhGexReply(val msg: SshMsgKexDhGexReply) : ReceiveKex()
        }
        object ReceiveNewKeys : SshEvent()
        data class ReceiveServiceAccept(val service: String) : SshEvent()
        object AuthenticationSuccess : SshEvent()
        object AuthenticationFailure : SshEvent()
        data class ReceiveDebug(val msg: SshMsgDebug) : SshEvent()
        object ReceiveIgnore : SshEvent()
        object Disconnect : SshEvent()
    }

    val stateMachine: StateMachine = createStdLibStateMachine {
        val waitVersion = state("WaitVersion")
        val waitKexInit = state("WaitKexInit")
        val waitKex = state("WaitKex")
        val waitNewKeys = state("WaitNewKeys")
        val waitService = state("WaitService")
        val waitAuthentication = state("WaitAuthentication")
        val connected = state("Connected")
        val disconnected = finalState("Disconnected")

        initialState("Unconnected") {
            onEntry { callbacks.onStateEnter("Unconnected") }
            onExit { callbacks.onStateExit("Unconnected") }

            transition<SshEvent.Connect> {
                targetState = waitVersion
                onTriggered {
                    callbacks.sendVersion()
                }
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
                    callbacks.sendKexDhInit()
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
                targetState = waitService
                onTriggered {
                    callbacks.receiveNewKeys()
                    callbacks.activateEncryption()
                    callbacks.sendServiceRequest("ssh-userauth")
                }
            }
        }

        waitService {
            onEntry { callbacks.onStateEnter("WaitService") }
            onExit { callbacks.onStateExit("WaitService") }

            transition<SshEvent.ReceiveServiceAccept> {
                targetState = waitAuthentication
                onTriggered {
                    callbacks.receiveServiceAccept(it.event.service)
                    callbacks.startAuthentication()
                }
            }
        }

        waitAuthentication {
            onEntry { callbacks.onStateEnter("WaitAuthentication") }
            onExit { callbacks.onStateExit("WaitAuthentication") }

            transition<SshEvent.AuthenticationSuccess> {
                targetState = connected
                onTriggered {
                    callbacks.authenticationSuccess()
                }
            }

            transition<SshEvent.AuthenticationFailure> {
                onTriggered {
                    callbacks.authenticationFailure()
                }
            }
        }

        connected {
            onEntry { callbacks.onStateEnter("Connected") }
            onExit { callbacks.onStateExit("Connected") }
        }

        disconnected {
            onEntry { callbacks.onStateEnter("Disconnected") }
        }

        transition<SshEvent.ReceiveDebug> {
            onTriggered {
                callbacks.debug(it.event.msg)
            }
        }

        transition<SshEvent.ReceiveIgnore> {
            onTriggered {
                callbacks.ignore()
            }
        }

        transition<SshEvent.Disconnect> {
            targetState = disconnected
            onTriggered {
                callbacks.disconnect()
            }
        }
    }

    fun processEvent(event: SshEvent) {
        stateMachine.processEventBlocking(event)
    }

    val currentState: String
        get() = stateMachine.activeStates().firstOrNull()?.name ?: "Unknown"

    fun isInState(stateName: String): Boolean {
        return stateMachine.activeStates().any { it.name == stateName }
    }
}

interface SshClientCallbacks {
    fun sendVersion()
    fun receiveVersion(banner: IdBanner)
    fun sendKexInit()
    fun receiveKexInit(msg: SshMsgKexinit)
    fun sendKexDhInit()
    fun receiveKexDhReply(msg: SshMsgKexdhReply)
    fun receiveKexEcdhReply(msg: SshMsgKexEcdhReply)
    fun receiveKexDhGexReply(msg: SshMsgKexDhGexReply)
    fun sendNewKeys()
    fun receiveNewKeys()
    fun activateEncryption()
    fun sendServiceRequest(service: String)
    fun receiveServiceAccept(service: String)
    fun startAuthentication()
    fun authenticationSuccess()
    fun authenticationFailure()
    fun debug(msg: SshMsgDebug)
    fun ignore()
    fun disconnect()
    fun onStateEnter(stateName: String)
    fun onStateExit(stateName: String)
}
