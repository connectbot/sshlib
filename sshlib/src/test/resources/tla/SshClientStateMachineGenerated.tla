---- MODULE SshClientStateMachineGenerated ----
\* Generated from SshClientStateMachine. Do not edit.
\* Model SHA-256: f9e4f8f1c7081bb708de019aedb963018bf45b44270a91bc44afd9eff6fb0c79
\* Lifecycle states: 11; transitions: 36.
\* TLC distinct states count full variable valuations, not lifecycle nodes.
EXTENDS Naturals

VARIABLES state, previousState, history, event, origin, packetWasParsed, effects, rekeying, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending

vars == <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending>>

States == {"Authenticated", "Authenticating", "AuthenticationReady", "Disconnected", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
PostAuthenticatedStates == {"Authenticated", "Authenticating", "AuthenticationReady"}
KexStates == {"WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys"}
Events == {"AuthenticationFailure", "AuthenticationSuccess", "AuthorizeAuthenticatedPacket", "AuthorizeAuthenticationPacket", "AuthorizeConnectionPacket", "AuthorizeExtInfo", "BeginAuthentication", "Connect", "Disconnect", "OpenChannel", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveDebug", "ReceiveGlobalRequest", "ReceiveIgnore", "ReceiveKex.DhGexGroup", "ReceiveKex.DhGexReply", "ReceiveKex.DhReply", "ReceiveKex.EcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyStarted", "SendChannelRequest", "UnexpectedKexInit"}
Origins == {"Internal", "LocalCommand", "ParsedPacket", "Timer"}
Effects == {"ActivateEncryption", "AuthenticationFailure", "AuthenticationSuccess", "Debug", "Disconnect", "Ignore", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveGlobalRequest", "ReceiveKexDhGexReply", "ReceiveKexDhReply", "ReceiveKexEcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyComplete", "RekeyStarted", "SendChannelOpen", "SendChannelRequest", "SendClientExtInfo", "SendKexDhGexInit", "SendKexExchangeInit", "SendKexInit", "SendNewKeys", "SendProtocolError", "SendServiceRequest", "SendUserauthRequest", "SendVersion", "StartAuthentication"}

Init ==
    /\ state = "Unconnected"
    /\ previousState = "Unconnected"
    /\ history = "AuthenticationReady"
    /\ event = "None"
    /\ origin = "Internal"
    /\ packetWasParsed = FALSE
    /\ effects = {}
    /\ rekeying = FALSE
    /\ authenticationEstablished = FALSE
    /\ initialNewKeysActive = FALSE
    /\ authRequestPending = FALSE
    /\ previousAuthRequestPending = FALSE

AUTHENTICATION_FAILURE ==
    /\ state \in {"Authenticating"}
    /\ state' = "AuthenticationReady"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthenticationFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"AuthenticationFailure"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

AUTHENTICATION_SUCCESS ==
    /\ state \in {"Authenticating"}
    /\ state' = "Authenticated"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthenticationSuccess"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"AuthenticationSuccess"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = TRUE
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

AUTHORIZE_AUTHENTICATED_PACKET ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeAuthenticatedPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

AUTHORIZE_AUTHENTICATION_PACKET ==
    /\ state \in {"Authenticating"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeAuthenticationPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

AUTHORIZE_CONNECTION_PACKET ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeConnectionPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

AUTHORIZE_POST_AUTH_EXT_INFO ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeExtInfo"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

AUTHORIZE_SERVICE_EXT_INFO ==
    /\ state \in {"WaitService"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeExtInfo"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

BEGIN_AUTHENTICATION ==
    /\ state \in {"AuthenticationReady"}
    /\ ~(authRequestPending)
    /\ state' = "Authenticating"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "BeginAuthentication"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendUserauthRequest"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = TRUE
    /\ previousAuthRequestPending' = authRequestPending

CONNECT ==
    /\ state \in {"Unconnected"}
    /\ state' = "WaitVersion"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "Connect"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendVersion"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

DISCONNECT ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "Disconnect"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect"}
    /\ rekeying' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

OPEN_CHANNEL ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "OpenChannel"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendChannelOpen"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_CHANNEL_FAILURE ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelFailure"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_CHANNEL_OPEN_CONFIRMATION ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelOpenConfirmation"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelOpenConfirmation"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_CHANNEL_OPEN_FAILURE ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelOpenFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelOpenFailure"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_CHANNEL_SUCCESS ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelSuccess"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelSuccess"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_DEBUG ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveDebug"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Debug"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_GLOBAL_REQUEST ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveGlobalRequest"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveGlobalRequest"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_IGNORE ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveIgnore"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Ignore"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_INITIAL_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ ~(rekeying)
    /\ state' = "WaitService"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNewKeys"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ActivateEncryption", "ReceiveNewKeys", "SendClientExtInfo", "SendServiceRequest"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = TRUE
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_KEX_DH_GEX_GROUP ==
    /\ state \in {"WaitKex"}
    /\ state' = "WaitKexDhGexInit"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.DhGexGroup"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendKexDhGexInit"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_KEX_DH_GEX_REPLY ==
    /\ state \in {"WaitKexDhGexInit"}
    /\ state' = "WaitNewKeys"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.DhGexReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexDhGexReply", "SendNewKeys"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_KEX_DH_REPLY ==
    /\ state \in {"WaitKex"}
    /\ state' = "WaitNewKeys"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.DhReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexDhReply", "SendNewKeys"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_KEX_ECDH_REPLY ==
    /\ state \in {"WaitKex"}
    /\ state' = "WaitNewKeys"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.EcdhReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexEcdhReply", "SendNewKeys"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_KEX_INIT ==
    /\ state \in {"WaitKexInit"}
    /\ state' = "WaitKex"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexInit", "SendKexExchangeInit"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_REKEY_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ rekeying
    /\ state' = history
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNewKeys"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ActivateEncryption", "ReceiveNewKeys", "RekeyComplete"}
    /\ rekeying' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = TRUE
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_SERVICE_ACCEPT ==
    /\ state \in {"WaitService"}
    /\ state' = "AuthenticationReady"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveServiceAccept"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveServiceAccept", "StartAuthentication"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_USERAUTH_BANNER_AUTHENTICATING ==
    /\ state \in {"Authenticating"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveUserauthBanner"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthBanner"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_USERAUTH_BANNER_READY ==
    /\ state \in {"AuthenticationReady"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveUserauthBanner"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthBanner"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_USERAUTH_INFO_REQUEST ==
    /\ state \in {"Authenticating"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveUserauthInfoRequest"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthInfoRequest"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

RECEIVE_VERSION ==
    /\ state \in {"WaitVersion"}
    /\ state' = "WaitKexInit"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveVersion"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveVersion", "SendKexInit"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

REKEY_STARTED ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ state' = "WaitKexInit"
    /\ previousState' = state
    /\ history' = state
    /\ event' = "RekeyStarted"
    /\ origin' \in {"LocalCommand", "ParsedPacket", "Timer"}
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"RekeyStarted", "SendKexInit"}
    /\ rekeying' = TRUE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

REPEAT_BEGIN_AUTHENTICATION ==
    /\ state \in {"Authenticating"}
    /\ ~(authRequestPending)
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "BeginAuthentication"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendUserauthRequest"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = TRUE
    /\ previousAuthRequestPending' = authRequestPending

SEND_CHANNEL_REQUEST ==
    /\ state \in {"Authenticated"}
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "SendChannelRequest"
    /\ origin' = "LocalCommand"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendChannelRequest"}
    /\ rekeying' = rekeying
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending

UNEXPECTED_KEX_INIT_WAIT_KEX ==
    /\ state \in {"WaitKex"}
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "UnexpectedKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT ==
    /\ state \in {"WaitKexDhGexInit"}
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "UnexpectedKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "UnexpectedKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending

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
    \/ UNEXPECTED_KEX_INIT_WAIT_KEX
    \/ UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT
    \/ UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS

Spec == Init /\ [][Next]_vars
====
