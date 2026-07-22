---- MODULE SshClientStateMachineGenerated ----
\* Generated from SshClientStateMachine. Do not edit.
\* Model SHA-256: 882c266edfb2fed9a28f79bc2ce7a5d343d87371ecfc9c9ca2ff42c467ed0a5f
\* Lifecycle states: 11; transitions: 36.
\* TLC distinct states count full variable valuations, not lifecycle nodes.
EXTENDS Naturals

CONSTANT MaxChannels

ChannelIDs == 1..MaxChannels
ChannelAttemptIDs == 0..(MaxChannels + 1)

VARIABLES state, previousState, history, event, origin, packetWasParsed, effects, rekeying, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending, previousChannels, activeChannel, channelEvent, channelOrigin, channels, channelEffects

vars == <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending, previousChannels, activeChannel, channelEvent, channelOrigin, channels, channelEffects>>

States == {"Authenticated", "Authenticating", "AuthenticationReady", "Disconnected", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
PostAuthenticatedStates == {"Authenticated", "Authenticating", "AuthenticationReady"}
KexStates == {"WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys"}
Events == {"AuthenticationFailure", "AuthenticationSuccess", "AuthorizeAuthenticatedPacket", "AuthorizeAuthenticationPacket", "AuthorizeConnectionPacket", "AuthorizeExtInfo", "BeginAuthentication", "Connect", "Disconnect", "OpenChannel", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveDebug", "ReceiveGlobalRequest", "ReceiveIgnore", "ReceiveKex.DhGexGroup", "ReceiveKex.DhGexReply", "ReceiveKex.DhReply", "ReceiveKex.EcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyStarted", "SendChannelRequest", "UnexpectedKexInit"}
Origins == {"Internal", "LocalCommand", "ParsedPacket", "Timer"}
Effects == {"ActivateEncryption", "AuthenticationFailure", "AuthenticationSuccess", "Debug", "Disconnect", "Ignore", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveGlobalRequest", "ReceiveKexDhGexReply", "ReceiveKexDhReply", "ReceiveKexEcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyComplete", "RekeyStarted", "SendChannelOpen", "SendChannelRequest", "SendClientExtInfo", "SendKexDhGexInit", "SendKexExchangeInit", "SendKexInit", "SendNewKeys", "SendProtocolError", "SendServiceRequest", "SendUserauthRequest", "SendVersion", "StartAuthentication"}

ChannelStates == {"BOTH_EOF", "CLOSED", "CLOSE_SENT", "LOCAL_EOF", "OPEN", "OPENING", "REMOTE_EOF", "Unallocated"}
ChannelEvents == {"AcceptRemoteOpen", "AllocateLocalOpen", "OpenConfirmed", "OpenFailed", "ReceiveClose", "ReceiveData", "ReceiveEof", "ReceiveRequest", "ReceiveWindowAdjust", "SendClose", "SendData", "SendEof", "SendRequest"}
ChannelAttemptEvents == {"AcceptRemoteOpen", "ReceiveClose", "ReceiveData", "ReceiveEof", "ReceiveRequest", "ReceiveWindowAdjust", "SendClose", "SendData", "SendEof"}
ChannelEffectSet == {"ADJUST_WINDOW", "CLOSE_CHANNEL", "CLOSE_INBOUND_STREAMS", "COMPLETE_OPEN", "DELIVER_DATA", "DELIVER_REQUEST", "FAIL_OPEN", "SEND_CLOSE", "SEND_DATA", "SEND_EOF", "SEND_OPEN", "SEND_OPEN_CONFIRMATION", "SEND_REQUEST"}
ChannelOrigins == {"ConnectionControl", "LocalCommand", "ParsedPacket"}
ChannelTransitions == {
    <<"BOTH_EOF", "ReceiveClose", "CLOSED">>,
    <<"BOTH_EOF", "ReceiveRequest", "BOTH_EOF">>,
    <<"BOTH_EOF", "ReceiveWindowAdjust", "BOTH_EOF">>,
    <<"BOTH_EOF", "SendClose", "CLOSE_SENT">>,
    <<"BOTH_EOF", "SendRequest", "BOTH_EOF">>,
    <<"CLOSE_SENT", "ReceiveClose", "CLOSED">>,
    <<"LOCAL_EOF", "ReceiveClose", "CLOSED">>,
    <<"LOCAL_EOF", "ReceiveData", "LOCAL_EOF">>,
    <<"LOCAL_EOF", "ReceiveEof", "BOTH_EOF">>,
    <<"LOCAL_EOF", "ReceiveRequest", "LOCAL_EOF">>,
    <<"LOCAL_EOF", "ReceiveWindowAdjust", "LOCAL_EOF">>,
    <<"LOCAL_EOF", "SendClose", "CLOSE_SENT">>,
    <<"LOCAL_EOF", "SendRequest", "LOCAL_EOF">>,
    <<"OPEN", "ReceiveClose", "CLOSED">>,
    <<"OPEN", "ReceiveData", "OPEN">>,
    <<"OPEN", "ReceiveEof", "REMOTE_EOF">>,
    <<"OPEN", "ReceiveRequest", "OPEN">>,
    <<"OPEN", "ReceiveWindowAdjust", "OPEN">>,
    <<"OPEN", "SendClose", "CLOSE_SENT">>,
    <<"OPEN", "SendData", "OPEN">>,
    <<"OPEN", "SendEof", "LOCAL_EOF">>,
    <<"OPEN", "SendRequest", "OPEN">>,
    <<"OPENING", "OpenConfirmed", "OPEN">>,
    <<"OPENING", "OpenFailed", "CLOSED">>,
    <<"REMOTE_EOF", "ReceiveClose", "CLOSED">>,
    <<"REMOTE_EOF", "ReceiveRequest", "REMOTE_EOF">>,
    <<"REMOTE_EOF", "ReceiveWindowAdjust", "REMOTE_EOF">>,
    <<"REMOTE_EOF", "SendClose", "CLOSE_SENT">>,
    <<"REMOTE_EOF", "SendData", "REMOTE_EOF">>,
    <<"REMOTE_EOF", "SendEof", "BOTH_EOF">>,
    <<"REMOTE_EOF", "SendRequest", "REMOTE_EOF">>,
    <<"Unallocated", "AcceptRemoteOpen", "OPEN">>,
    <<"Unallocated", "AllocateLocalOpen", "OPENING">>
}
ChannelAuthenticationRequired == {
    <<"BOTH_EOF", "ReceiveClose">>,
    <<"BOTH_EOF", "ReceiveRequest">>,
    <<"BOTH_EOF", "ReceiveWindowAdjust">>,
    <<"BOTH_EOF", "SendClose">>,
    <<"BOTH_EOF", "SendRequest">>,
    <<"CLOSE_SENT", "ReceiveClose">>,
    <<"LOCAL_EOF", "ReceiveClose">>,
    <<"LOCAL_EOF", "ReceiveData">>,
    <<"LOCAL_EOF", "ReceiveEof">>,
    <<"LOCAL_EOF", "ReceiveRequest">>,
    <<"LOCAL_EOF", "ReceiveWindowAdjust">>,
    <<"LOCAL_EOF", "SendClose">>,
    <<"LOCAL_EOF", "SendRequest">>,
    <<"OPEN", "ReceiveClose">>,
    <<"OPEN", "ReceiveData">>,
    <<"OPEN", "ReceiveEof">>,
    <<"OPEN", "ReceiveRequest">>,
    <<"OPEN", "ReceiveWindowAdjust">>,
    <<"OPEN", "SendClose">>,
    <<"OPEN", "SendData">>,
    <<"OPEN", "SendEof">>,
    <<"OPEN", "SendRequest">>,
    <<"OPENING", "OpenConfirmed">>,
    <<"OPENING", "OpenFailed">>,
    <<"REMOTE_EOF", "ReceiveClose">>,
    <<"REMOTE_EOF", "ReceiveRequest">>,
    <<"REMOTE_EOF", "ReceiveWindowAdjust">>,
    <<"REMOTE_EOF", "SendClose">>,
    <<"REMOTE_EOF", "SendData">>,
    <<"REMOTE_EOF", "SendEof">>,
    <<"REMOTE_EOF", "SendRequest">>,
    <<"Unallocated", "AcceptRemoteOpen">>,
    <<"Unallocated", "AllocateLocalOpen">>
}

ChannelTransitionDefined(channelState, operation) ==
    \E target \in ChannelStates : <<channelState, operation, target>> \in ChannelTransitions

ChannelTransitionTarget(channelState, operation) ==
    CHOOSE target \in ChannelStates : <<channelState, operation, target>> \in ChannelTransitions

ChannelEffectsFor(channelState, operation) ==
    CASE /\ channelState = "BOTH_EOF" /\ operation = "ReceiveClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "BOTH_EOF" /\ operation = "ReceiveRequest" -> {"DELIVER_REQUEST"}
      [] /\ channelState = "BOTH_EOF" /\ operation = "ReceiveWindowAdjust" -> {"ADJUST_WINDOW"}
      [] /\ channelState = "BOTH_EOF" /\ operation = "SendClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "BOTH_EOF" /\ operation = "SendRequest" -> {"SEND_REQUEST"}
      [] /\ channelState = "CLOSE_SENT" /\ operation = "ReceiveClose" -> {"CLOSE_CHANNEL"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "ReceiveClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "ReceiveData" -> {"DELIVER_DATA"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "ReceiveEof" -> {"CLOSE_INBOUND_STREAMS"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "ReceiveRequest" -> {"DELIVER_REQUEST"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "ReceiveWindowAdjust" -> {"ADJUST_WINDOW"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "SendClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "LOCAL_EOF" /\ operation = "SendRequest" -> {"SEND_REQUEST"}
      [] /\ channelState = "OPEN" /\ operation = "ReceiveClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "OPEN" /\ operation = "ReceiveData" -> {"DELIVER_DATA"}
      [] /\ channelState = "OPEN" /\ operation = "ReceiveEof" -> {"CLOSE_INBOUND_STREAMS"}
      [] /\ channelState = "OPEN" /\ operation = "ReceiveRequest" -> {"DELIVER_REQUEST"}
      [] /\ channelState = "OPEN" /\ operation = "ReceiveWindowAdjust" -> {"ADJUST_WINDOW"}
      [] /\ channelState = "OPEN" /\ operation = "SendClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "OPEN" /\ operation = "SendData" -> {"SEND_DATA"}
      [] /\ channelState = "OPEN" /\ operation = "SendEof" -> {"SEND_EOF"}
      [] /\ channelState = "OPEN" /\ operation = "SendRequest" -> {"SEND_REQUEST"}
      [] /\ channelState = "OPENING" /\ operation = "OpenConfirmed" -> {"COMPLETE_OPEN"}
      [] /\ channelState = "OPENING" /\ operation = "OpenFailed" -> {"FAIL_OPEN"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "ReceiveClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "ReceiveRequest" -> {"DELIVER_REQUEST"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "ReceiveWindowAdjust" -> {"ADJUST_WINDOW"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "SendClose" -> {"SEND_CLOSE", "CLOSE_CHANNEL"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "SendData" -> {"SEND_DATA"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "SendEof" -> {"SEND_EOF"}
      [] /\ channelState = "REMOTE_EOF" /\ operation = "SendRequest" -> {"SEND_REQUEST"}
      [] /\ channelState = "Unallocated" /\ operation = "AcceptRemoteOpen" -> {"SEND_OPEN_CONFIRMATION"}
      [] /\ channelState = "Unallocated" /\ operation = "AllocateLocalOpen" -> {"SEND_OPEN"}
      [] OTHER -> {}

ChannelOriginFor(operation) ==
    CASE  operation = "ReceiveClose" -> "ParsedPacket"
      []  operation = "ReceiveRequest" -> "ParsedPacket"
      []  operation = "ReceiveWindowAdjust" -> "ParsedPacket"
      []  operation = "SendClose" -> "LocalCommand"
      []  operation = "SendRequest" -> "LocalCommand"
      []  operation = "ReceiveData" -> "ParsedPacket"
      []  operation = "ReceiveEof" -> "ParsedPacket"
      []  operation = "SendData" -> "LocalCommand"
      []  operation = "SendEof" -> "LocalCommand"
      []  operation = "OpenConfirmed" -> "ParsedPacket"
      []  operation = "OpenFailed" -> "ParsedPacket"
      []  operation = "AcceptRemoteOpen" -> "ParsedPacket"
      []  operation = "AllocateLocalOpen" -> "LocalCommand"
      [] OTHER -> "None"

ChannelOperationAllowed(isAuthenticated, connectionState, channelState, operation) ==
    /\ ChannelTransitionDefined(channelState, operation)
    /\ connectionState # "Disconnected"
    /\ (<<channelState, operation>> \notin ChannelAuthenticationRequired
        \/ isAuthenticated)

AttemptChannelOperation ==
    /\ activeChannel' \in ChannelAttemptIDs
    /\ channelEvent' \in ChannelAttemptEvents
    /\ channelOrigin' = ChannelOriginFor(channelEvent')
    /\ previousChannels' = channels
    /\ IF activeChannel' \in ChannelIDs
          /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], channelEvent')
       THEN
          /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], channelEvent')]
          /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], channelEvent')
       ELSE
          /\ channels' = channels
          /\ channelEffects' = {}
    /\ UNCHANGED <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending>>

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
    /\ previousChannels = [c \in ChannelIDs |-> "Unallocated"]
    /\ activeChannel = 0
    /\ channelEvent = "None"
    /\ channelOrigin = "None"
    /\ channels = [c \in ChannelIDs |-> "Unallocated"]
    /\ channelEffects = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "AllocateLocalOpen")
    /\ channelEvent' = "AllocateLocalOpen"
    /\ channelOrigin' = ChannelOriginFor("AllocateLocalOpen")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "AllocateLocalOpen")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "AllocateLocalOpen")

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "OpenConfirmed")
    /\ channelEvent' = "OpenConfirmed"
    /\ channelOrigin' = ChannelOriginFor("OpenConfirmed")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "OpenConfirmed")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "OpenConfirmed")

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
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "OpenFailed")
    /\ channelEvent' = "OpenFailed"
    /\ channelOrigin' = ChannelOriginFor("OpenFailed")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "OpenFailed")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "OpenFailed")

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "SendRequest")
    /\ channelEvent' = "SendRequest"
    /\ channelOrigin' = ChannelOriginFor("SendRequest")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "SendRequest")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "SendRequest")

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

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
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

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
    \/ AttemptChannelOperation

Spec == Init /\ [][Next]_vars
====
