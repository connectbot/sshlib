---- MODULE SshClientStateMachineGenerated ----
\* Generated from SshClientStateMachine. Do not edit.
\* Model SHA-256: 091cf5eb3bf082c601ebd326ed89f36cd2f4ff2973c3f29de16fba05f376dde8
\* Lifecycle states: 11; transitions: 33.
\* TLC distinct states count full variable valuations, not lifecycle nodes.
EXTENDS Naturals

VARIABLES state, previousState, history, event, origin, packetWasParsed, effects, rekeying

vars == <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying>>

States == {"Authenticated", "Authenticating", "AuthenticationReady", "Disconnected", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
PostAuthenticatedStates == {"Authenticated", "Authenticating", "AuthenticationReady"}
Events == {"AuthenticationFailure", "AuthenticationSuccess", "AuthorizeAuthenticatedPacket", "AuthorizeAuthenticationPacket", "AuthorizeConnectionPacket", "AuthorizeExtInfo", "BeginAuthentication", "Connect", "Disconnect", "OpenChannel", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveDebug", "ReceiveGlobalRequest", "ReceiveIgnore", "ReceiveKex.DhGexGroup", "ReceiveKex.DhGexReply", "ReceiveKex.DhReply", "ReceiveKex.EcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyStarted", "SendChannelRequest"}
Origins == {"Internal", "LocalCommand", "ParsedPacket", "Timer"}
Effects == {"ActivateEncryption", "AuthenticationFailure", "AuthenticationSuccess", "Debug", "Disconnect", "Ignore", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveGlobalRequest", "ReceiveKexDhGexReply", "ReceiveKexDhReply", "ReceiveKexEcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyComplete", "RekeyStarted", "SendChannelOpen", "SendChannelRequest", "SendClientExtInfo", "SendKexDhGexInit", "SendKexExchangeInit", "SendKexInit", "SendNewKeys", "SendServiceRequest", "SendVersion", "StartAuthentication"}

Init ==
    /\ state = "Unconnected"
    /\ previousState = "Unconnected"
    /\ history = "AuthenticationReady"
    /\ event = "None"
    /\ origin = "Internal"
    /\ packetWasParsed = FALSE
    /\ effects = {}
    /\ rekeying = FALSE

AUTHENTICATION_FAILURE ==
    /\ state \in {"Authenticating"}
    /\ event' = "AuthenticationFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"AuthenticationFailure"}
    /\ previousState' = state
    /\ state' = "AuthenticationReady"
    /\ history' = history
    /\ rekeying' = rekeying

AUTHENTICATION_SUCCESS ==
    /\ state \in {"Authenticating"}
    /\ event' = "AuthenticationSuccess"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"AuthenticationSuccess"}
    /\ previousState' = state
    /\ state' = "Authenticated"
    /\ history' = history
    /\ rekeying' = rekeying

AUTHORIZE_AUTHENTICATED_PACKET ==
    /\ state \in {"Authenticated"}
    /\ event' = "AuthorizeAuthenticatedPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

AUTHORIZE_AUTHENTICATION_PACKET ==
    /\ state \in {"Authenticating"}
    /\ event' = "AuthorizeAuthenticationPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

AUTHORIZE_CONNECTION_PACKET ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ event' = "AuthorizeConnectionPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

AUTHORIZE_POST_AUTH_EXT_INFO ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ event' = "AuthorizeExtInfo"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

AUTHORIZE_SERVICE_EXT_INFO ==
    /\ state \in {"WaitService"}
    /\ event' = "AuthorizeExtInfo"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

BEGIN_AUTHENTICATION ==
    /\ state \in {"AuthenticationReady"}
    /\ event' = "BeginAuthentication"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = "Authenticating"
    /\ history' = history
    /\ rekeying' = rekeying

CONNECT ==
    /\ state \in {"Unconnected"}
    /\ event' = "Connect"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendVersion"}
    /\ previousState' = state
    /\ state' = "WaitVersion"
    /\ history' = history
    /\ rekeying' = rekeying

DISCONNECT ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ event' = "Disconnect"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect"}
    /\ previousState' = state
    /\ state' = "Disconnected"
    /\ history' = history
    /\ rekeying' = rekeying

OPEN_CHANNEL ==
    /\ state \in {"Authenticated"}
    /\ event' = "OpenChannel"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendChannelOpen"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_CHANNEL_FAILURE ==
    /\ state \in {"Authenticated"}
    /\ event' = "ReceiveChannelFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelFailure"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_CHANNEL_OPEN_CONFIRMATION ==
    /\ state \in {"Authenticated"}
    /\ event' = "ReceiveChannelOpenConfirmation"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelOpenConfirmation"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_CHANNEL_OPEN_FAILURE ==
    /\ state \in {"Authenticated"}
    /\ event' = "ReceiveChannelOpenFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelOpenFailure"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_CHANNEL_SUCCESS ==
    /\ state \in {"Authenticated"}
    /\ event' = "ReceiveChannelSuccess"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelSuccess"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_DEBUG ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ event' = "ReceiveDebug"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Debug"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_GLOBAL_REQUEST ==
    /\ state \in {"Authenticated"}
    /\ event' = "ReceiveGlobalRequest"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveGlobalRequest"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_IGNORE ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ event' = "ReceiveIgnore"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Ignore"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_INITIAL_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ ~(rekeying)
    /\ event' = "ReceiveNewKeys"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ActivateEncryption", "ReceiveNewKeys", "SendClientExtInfo", "SendServiceRequest"}
    /\ previousState' = state
    /\ state' = "WaitService"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_KEX_DH_GEX_GROUP ==
    /\ state \in {"WaitKex"}
    /\ event' = "ReceiveKex.DhGexGroup"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendKexDhGexInit"}
    /\ previousState' = state
    /\ state' = "WaitKexDhGexInit"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_KEX_DH_GEX_REPLY ==
    /\ state \in {"WaitKexDhGexInit"}
    /\ event' = "ReceiveKex.DhGexReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexDhGexReply", "SendNewKeys"}
    /\ previousState' = state
    /\ state' = "WaitNewKeys"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_KEX_DH_REPLY ==
    /\ state \in {"WaitKex"}
    /\ event' = "ReceiveKex.DhReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexDhReply", "SendNewKeys"}
    /\ previousState' = state
    /\ state' = "WaitNewKeys"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_KEX_ECDH_REPLY ==
    /\ state \in {"WaitKex"}
    /\ event' = "ReceiveKex.EcdhReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexEcdhReply", "SendNewKeys"}
    /\ previousState' = state
    /\ state' = "WaitNewKeys"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_KEX_INIT ==
    /\ state \in {"WaitKexInit"}
    /\ event' = "ReceiveKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexInit", "SendKexExchangeInit"}
    /\ previousState' = state
    /\ state' = "WaitKex"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_REKEY_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ rekeying
    /\ event' = "ReceiveNewKeys"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ActivateEncryption", "ReceiveNewKeys", "RekeyComplete"}
    /\ previousState' = state
    /\ state' = history
    /\ history' = history
    /\ rekeying' = FALSE

RECEIVE_SERVICE_ACCEPT ==
    /\ state \in {"WaitService"}
    /\ event' = "ReceiveServiceAccept"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveServiceAccept", "StartAuthentication"}
    /\ previousState' = state
    /\ state' = "AuthenticationReady"
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_USERAUTH_BANNER_AUTHENTICATING ==
    /\ state \in {"Authenticating"}
    /\ event' = "ReceiveUserauthBanner"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthBanner"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_USERAUTH_BANNER_READY ==
    /\ state \in {"AuthenticationReady"}
    /\ event' = "ReceiveUserauthBanner"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthBanner"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_USERAUTH_INFO_REQUEST ==
    /\ state \in {"Authenticating"}
    /\ event' = "ReceiveUserauthInfoRequest"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthInfoRequest"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

RECEIVE_VERSION ==
    /\ state \in {"WaitVersion"}
    /\ event' = "ReceiveVersion"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveVersion", "SendKexInit"}
    /\ previousState' = state
    /\ state' = "WaitKexInit"
    /\ history' = history
    /\ rekeying' = rekeying

REKEY_STARTED ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ event' = "RekeyStarted"
    /\ origin' \in {"LocalCommand", "ParsedPacket", "Timer"}
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"RekeyStarted", "SendKexInit"}
    /\ previousState' = state
    /\ state' = "WaitKexInit"
    /\ history' = state
    /\ rekeying' = TRUE

REPEAT_BEGIN_AUTHENTICATION ==
    /\ state \in {"Authenticating"}
    /\ event' = "BeginAuthentication"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

SEND_CHANNEL_REQUEST ==
    /\ state \in {"Authenticated"}
    /\ event' = "SendChannelRequest"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendChannelRequest"}
    /\ previousState' = state
    /\ state' = state
    /\ history' = history
    /\ rekeying' = rekeying

Next ==
    \/ AUTHENTICATION_FAILURE
    \/ AUTHENTICATION_SUCCESS
    \/ AUTHORIZE_AUTHENTICATED_PACKET
    \/ AUTHORIZE_AUTHENTICATION_PACKET
    \/ AUTHORIZE_CONNECTION_PACKET
    \/ AUTHORIZE_POST_AUTH_EXT_INFO
    \/ AUTHORIZE_SERVICE_EXT_INFO
    \/ BEGIN_AUTHENTICATION
    \/ CONNECT
    \/ DISCONNECT
    \/ OPEN_CHANNEL
    \/ RECEIVE_CHANNEL_FAILURE
    \/ RECEIVE_CHANNEL_OPEN_CONFIRMATION
    \/ RECEIVE_CHANNEL_OPEN_FAILURE
    \/ RECEIVE_CHANNEL_SUCCESS
    \/ RECEIVE_DEBUG
    \/ RECEIVE_GLOBAL_REQUEST
    \/ RECEIVE_IGNORE
    \/ RECEIVE_INITIAL_NEW_KEYS
    \/ RECEIVE_KEX_DH_GEX_GROUP
    \/ RECEIVE_KEX_DH_GEX_REPLY
    \/ RECEIVE_KEX_DH_REPLY
    \/ RECEIVE_KEX_ECDH_REPLY
    \/ RECEIVE_KEX_INIT
    \/ RECEIVE_REKEY_NEW_KEYS
    \/ RECEIVE_SERVICE_ACCEPT
    \/ RECEIVE_USERAUTH_BANNER_AUTHENTICATING
    \/ RECEIVE_USERAUTH_BANNER_READY
    \/ RECEIVE_USERAUTH_INFO_REQUEST
    \/ RECEIVE_VERSION
    \/ REKEY_STARTED
    \/ REPEAT_BEGIN_AUTHENTICATION
    \/ SEND_CHANNEL_REQUEST

Spec == Init /\ [][Next]_vars
====
