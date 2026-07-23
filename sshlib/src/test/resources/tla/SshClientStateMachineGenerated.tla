---- MODULE SshClientStateMachineGenerated ----
\* Generated from SshClientStateMachine. Do not edit.
\* Model SHA-256: 51a83d84a0f081b32e4dfcf4d185ef2c83fec2c9a640b385db78f35607733b78
\* Lifecycle states: 11; transitions: 43.
\* TLC distinct states count full variable valuations, not lifecycle nodes.
EXTENDS Naturals

CONSTANTS MaxChannels, EnableHostileEnvironment, AdversaryOwnsHostKey, EnforceKexProofVerification

ChannelIDs == 1..MaxChannels
ChannelAttemptIDs == 0..(MaxChannels + 1)

VARIABLES state, previousState, history, event, origin, packetWasParsed, effects, rekeying, strictKex, nonKexBeforeInitialKexInit, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending, inboundPacket, lastInboundPacket, inboundTranscriptMatches, inboundHostSignatureValid, inboundTransportValid, hostKeyPossessionVerified, transcriptVerified, transportKeysVerified, lastPacketDisposition, previousChannels, activeChannel, channelEvent, channelOrigin, channels, channelEffects

vars == <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying, strictKex, nonKexBeforeInitialKexInit, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending, inboundPacket, lastInboundPacket, inboundTranscriptMatches, inboundHostSignatureValid, inboundTransportValid, hostKeyPossessionVerified, transcriptVerified, transportKeysVerified, lastPacketDisposition, previousChannels, activeChannel, channelEvent, channelOrigin, channels, channelEffects>>

States == {"Authenticated", "Authenticating", "AuthenticationReady", "Disconnected", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
PostAuthenticatedStates == {"Authenticated", "Authenticating", "AuthenticationReady"}
KexStates == {"WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys"}
Events == {"AuthenticationFailure", "AuthenticationSuccess", "AuthorizeAuthenticatedPacket", "AuthorizeAuthenticationPacket", "AuthorizeConnectionPacket", "AuthorizeExtInfo", "BeginAuthentication", "Connect", "Disconnect", "HostilePacketRejected", "OpenChannel", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveDebug", "ReceiveGlobalRequest", "ReceiveIgnore", "ReceiveInitialNonStrictKexInit", "ReceiveInitialStrictKexInit", "ReceiveKex.DhGexGroup", "ReceiveKex.DhGexReply", "ReceiveKex.DhReply", "ReceiveKex.EcdhReply", "ReceiveNewKeys", "ReceiveNonKexPacket", "ReceiveRekeyKexInit", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RekeyStarted", "SendChannelRequest", "UnexpectedKexInit"}
Origins == {"Internal", "LocalCommand", "ParsedPacket", "Timer"}
Effects == {"ActivateEncryption", "ActivateInboundProtection", "ActivateOutboundProtection", "AuthenticationFailure", "AuthenticationSuccess", "ClearNonKexBeforeInitialKexInit", "Debug", "Disconnect", "EnableStrictKex", "Ignore", "NegotiateNonStrictKex", "ReceiveChannelFailure", "ReceiveChannelOpenConfirmation", "ReceiveChannelOpenFailure", "ReceiveChannelSuccess", "ReceiveGlobalRequest", "ReceiveKexDhGexReply", "ReceiveKexDhReply", "ReceiveKexEcdhReply", "ReceiveKexInit", "ReceiveNewKeys", "ReceiveServiceAccept", "ReceiveUserauthBanner", "ReceiveUserauthInfoRequest", "ReceiveVersion", "RecordNonKexBeforeInitialKexInit", "RekeyComplete", "RekeyStarted", "ResetInboundSequence", "ResetOutboundSequence", "SendChannelOpen", "SendChannelRequest", "SendClientExtInfo", "SendKexDhGexInit", "SendKexExchangeInit", "SendKexInit", "SendNewKeys", "SendProtocolError", "SendServiceRequest", "SendUnimplemented", "SendUserauthRequest", "SendVersion", "StartAuthentication", "VerifyHostKeyPossession", "VerifyKexTranscript"}
PacketClasses == {"ChannelOpenReply", "ChannelRequestReply", "ClientConnectionPacket", "ClientKexInit", "ClientServiceRequest", "ClientUserauthRequest", "ConnectionPacket", "Debug", "Disconnect", "ExtInfo", "GlobalRequest", "Ignore", "KexGexGroup", "KexInit", "KexReply", "NewKeys", "ServiceAccept", "Unknown", "UserauthBanner", "UserauthFailure", "UserauthMethodSpecific", "UserauthSuccess"}
PacketDispositions == {"None", "Client", "Accepted", "Unimplemented", "Disconnected"}

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
    /\ UNCHANGED <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying, strictKex, nonKexBeforeInitialKexInit, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending, inboundPacket, lastInboundPacket, inboundTranscriptMatches, inboundHostSignatureValid, inboundTransportValid, hostKeyPossessionVerified, transcriptVerified, transportKeysVerified, lastPacketDisposition>>

Init ==
    /\ state = "Unconnected"
    /\ previousState = "Unconnected"
    /\ history = "AuthenticationReady"
    /\ event = "None"
    /\ origin = "Internal"
    /\ packetWasParsed = FALSE
    /\ effects = {}
    /\ rekeying = FALSE
    /\ strictKex = FALSE
    /\ nonKexBeforeInitialKexInit = FALSE
    /\ authenticationEstablished = FALSE
    /\ initialNewKeysActive = FALSE
    /\ authRequestPending = FALSE
    /\ previousAuthRequestPending = FALSE
    /\ inboundPacket = "None"
    /\ lastInboundPacket = "None"
    /\ inboundTranscriptMatches = FALSE
    /\ inboundHostSignatureValid = FALSE
    /\ inboundTransportValid = FALSE
    /\ hostKeyPossessionVerified = FALSE
    /\ transcriptVerified = FALSE
    /\ transportKeysVerified = FALSE
    /\ lastPacketDisposition = "None"
    /\ previousChannels = [c \in ChannelIDs |-> "Unallocated"]
    /\ activeChannel = 0
    /\ channelEvent = "None"
    /\ channelOrigin = "None"
    /\ channels = [c \in ChannelIDs |-> "Unallocated"]
    /\ channelEffects = {}

AUTHENTICATION_FAILURE ==
    /\ state \in {"Authenticating"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"UserauthFailure"}
              /\ inboundTransportValid
       )
    /\ state' = "AuthenticationReady"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthenticationFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"AuthenticationFailure"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

AUTHENTICATION_SUCCESS ==
    /\ state \in {"Authenticating"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"UserauthSuccess"}
              /\ inboundTransportValid
       )
    /\ state' = "Authenticated"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthenticationSuccess"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"AuthenticationSuccess"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = TRUE
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

AUTHORIZE_AUTHENTICATED_PACKET ==
    /\ state \in {"Authenticated"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ConnectionPacket", "ClientConnectionPacket"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeAuthenticatedPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

AUTHORIZE_AUTHENTICATION_PACKET ==
    /\ state \in {"Authenticating"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"UserauthMethodSpecific"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeAuthenticationPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

AUTHORIZE_CONNECTION_PACKET ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ConnectionPacket"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeConnectionPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

AUTHORIZE_POST_AUTH_EXT_INFO ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ExtInfo"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeExtInfo"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

AUTHORIZE_SERVICE_EXT_INFO ==
    /\ state \in {"WaitService"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ExtInfo"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "AuthorizeExtInfo"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = TRUE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

DISCONNECT ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"Disconnect"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "Disconnect"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "AllocateLocalOpen")
    /\ channelEvent' = "AllocateLocalOpen"
    /\ channelOrigin' = ChannelOriginFor("AllocateLocalOpen")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "AllocateLocalOpen")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "AllocateLocalOpen")

RECEIVE_CHANNEL_FAILURE ==
    /\ state \in {"Authenticated"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ChannelRequestReply"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelFailure"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_CHANNEL_OPEN_CONFIRMATION ==
    /\ state \in {"Authenticated"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ChannelOpenReply"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelOpenConfirmation"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelOpenConfirmation"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "OpenConfirmed")
    /\ channelEvent' = "OpenConfirmed"
    /\ channelOrigin' = ChannelOriginFor("OpenConfirmed")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "OpenConfirmed")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "OpenConfirmed")

RECEIVE_CHANNEL_OPEN_FAILURE ==
    /\ state \in {"Authenticated"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ChannelOpenReply"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelOpenFailure"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelOpenFailure"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "OpenFailed")
    /\ channelEvent' = "OpenFailed"
    /\ channelOrigin' = ChannelOriginFor("OpenFailed")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "OpenFailed")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "OpenFailed")

RECEIVE_CHANNEL_SUCCESS ==
    /\ state \in {"Authenticated"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ChannelRequestReply"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveChannelSuccess"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveChannelSuccess"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_DEBUG ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"Debug"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveDebug"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Debug"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_GLOBAL_REQUEST ==
    /\ state \in {"Authenticated"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"GlobalRequest"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveGlobalRequest"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveGlobalRequest"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_IGNORE ==
    /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"Ignore"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveIgnore"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Ignore"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_INITIAL_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ ~(rekeying)
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"NewKeys"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ (~EnforceKexProofVerification \/ hostKeyPossessionVerified)
    /\ (~EnforceKexProofVerification \/ transcriptVerified)
    /\ state' = "WaitService"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNewKeys"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = IF strictKex THEN {"ActivateEncryption", "ActivateInboundProtection", "ReceiveNewKeys", "ResetInboundSequence", "SendClientExtInfo", "SendServiceRequest"} ELSE {"ActivateEncryption", "ActivateInboundProtection", "ReceiveNewKeys", "SendClientExtInfo", "SendServiceRequest"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = TRUE
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = TRUE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_INITIAL_NON_STRICT_KEX_INIT ==
    /\ state \in {"WaitKexInit"}
    /\ ~(rekeying)
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitKex"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveInitialNonStrictKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ClearNonKexBeforeInitialKexInit", "NegotiateNonStrictKex", "ReceiveKexInit", "SendKexExchangeInit"}
    /\ rekeying' = rekeying
    /\ strictKex' = FALSE
    /\ nonKexBeforeInitialKexInit' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_INITIAL_STRICT_KEX_INIT ==
    /\ state \in {"WaitKexInit"}
    /\ (~(rekeying)) /\ (~(nonKexBeforeInitialKexInit))
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitKex"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveInitialStrictKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ClearNonKexBeforeInitialKexInit", "EnableStrictKex", "ReceiveKexInit", "SendKexExchangeInit"}
    /\ rekeying' = rekeying
    /\ strictKex' = TRUE
    /\ nonKexBeforeInitialKexInit' = FALSE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_KEX_DH_GEX_GROUP ==
    /\ state \in {"WaitKex"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexGexGroup"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitKexDhGexInit"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.DhGexGroup"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"SendKexDhGexInit"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_KEX_DH_GEX_REPLY ==
    /\ state \in {"WaitKexDhGexInit"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexReply"}
              /\ (~EnforceKexProofVerification \/ inboundHostSignatureValid)
              /\ (~EnforceKexProofVerification \/ inboundTranscriptMatches)
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitNewKeys"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.DhGexReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = IF strictKex THEN {"ActivateOutboundProtection", "ReceiveKexDhGexReply", "ResetOutboundSequence", "SendNewKeys", "VerifyHostKeyPossession", "VerifyKexTranscript"} ELSE {"ActivateOutboundProtection", "ReceiveKexDhGexReply", "SendNewKeys", "VerifyHostKeyPossession", "VerifyKexTranscript"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = TRUE
    /\ transcriptVerified' = TRUE
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_KEX_DH_REPLY ==
    /\ state \in {"WaitKex"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexReply"}
              /\ (~EnforceKexProofVerification \/ inboundHostSignatureValid)
              /\ (~EnforceKexProofVerification \/ inboundTranscriptMatches)
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitNewKeys"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.DhReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = IF strictKex THEN {"ActivateOutboundProtection", "ReceiveKexDhReply", "ResetOutboundSequence", "SendNewKeys", "VerifyHostKeyPossession", "VerifyKexTranscript"} ELSE {"ActivateOutboundProtection", "ReceiveKexDhReply", "SendNewKeys", "VerifyHostKeyPossession", "VerifyKexTranscript"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = TRUE
    /\ transcriptVerified' = TRUE
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_KEX_ECDH_REPLY ==
    /\ state \in {"WaitKex"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexReply"}
              /\ (~EnforceKexProofVerification \/ inboundHostSignatureValid)
              /\ (~EnforceKexProofVerification \/ inboundTranscriptMatches)
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitNewKeys"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveKex.EcdhReply"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = IF strictKex THEN {"ActivateOutboundProtection", "ReceiveKexEcdhReply", "ResetOutboundSequence", "SendNewKeys", "VerifyHostKeyPossession", "VerifyKexTranscript"} ELSE {"ActivateOutboundProtection", "ReceiveKexEcdhReply", "SendNewKeys", "VerifyHostKeyPossession", "VerifyKexTranscript"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = TRUE
    /\ transcriptVerified' = TRUE
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_REKEY_KEX_INIT ==
    /\ state \in {"WaitKexInit"}
    /\ rekeying
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "WaitKex"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveRekeyKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveKexInit", "SendKexExchangeInit"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_REKEY_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ rekeying
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"NewKeys"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ (~EnforceKexProofVerification \/ hostKeyPossessionVerified)
    /\ (~EnforceKexProofVerification \/ transcriptVerified)
    /\ state' = history
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNewKeys"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = IF strictKex THEN {"ActivateEncryption", "ActivateInboundProtection", "ReceiveNewKeys", "RekeyComplete", "ResetInboundSequence"} ELSE {"ActivateEncryption", "ActivateInboundProtection", "ReceiveNewKeys", "RekeyComplete"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = TRUE
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = TRUE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_SERVICE_ACCEPT ==
    /\ state \in {"WaitService"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"ServiceAccept"}
              /\ inboundTransportValid
       )
    /\ state' = "AuthenticationReady"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveServiceAccept"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveServiceAccept", "StartAuthentication"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_USERAUTH_BANNER_AUTHENTICATING ==
    /\ state \in {"Authenticating"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"UserauthBanner"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveUserauthBanner"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthBanner"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_USERAUTH_BANNER_READY ==
    /\ state \in {"AuthenticationReady"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"UserauthBanner"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveUserauthBanner"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthBanner"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECEIVE_USERAUTH_INFO_REQUEST ==
    /\ state \in {"Authenticating"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"UserauthMethodSpecific"}
              /\ inboundTransportValid
       )
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveUserauthInfoRequest"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"ReceiveUserauthInfoRequest"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

RECORD_NON_KEX_BEFORE_INITIAL_KEX_INIT ==
    /\ state \in {"WaitKexInit"}
    /\ ~(rekeying)
    /\ state' = state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNonKexPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"RecordNonKexBeforeInitialKexInit"}
    /\ rekeying' = rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = TRUE
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = channels
    /\ channelEffects' = {}

REJECT_NON_KEX_WAIT_KEX ==
    /\ state \in {"WaitKex"}
    /\ (strictKex) /\ (~(rekeying))
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNonKexPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

REJECT_NON_KEX_WAIT_KEX_DH_GEX_INIT ==
    /\ state \in {"WaitKexDhGexInit"}
    /\ (strictKex) /\ (~(rekeying))
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNonKexPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

REJECT_NON_KEX_WAIT_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ (strictKex) /\ (~(rekeying))
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveNonKexPacket"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

REJECT_STRICT_KEX_INIT_NOT_FIRST ==
    /\ state \in {"WaitKexInit"}
    /\ (~(rekeying)) /\ (nonKexBeforeInitialKexInit)
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "ReceiveInitialStrictKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "EnableStrictKex", "ReceiveKexInit", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = TRUE
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = TRUE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
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
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = inboundPacket
    /\ lastInboundPacket' = lastInboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = hostKeyPossessionVerified
    /\ transcriptVerified' = transcriptVerified
    /\ transportKeysVerified' = transportKeysVerified
    /\ lastPacketDisposition' = "Client"
    /\ previousChannels' = channels
    /\ activeChannel' \in ChannelIDs /\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], "SendRequest")
    /\ channelEvent' = "SendRequest"
    /\ channelOrigin' = ChannelOriginFor("SendRequest")
    /\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], "SendRequest")]
    /\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], "SendRequest")

UNEXPECTED_KEX_INIT_WAIT_KEX ==
    /\ state \in {"WaitKex"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "UnexpectedKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT ==
    /\ state \in {"WaitKexDhGexInit"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "UnexpectedKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS ==
    /\ state \in {"WaitNewKeys"}
    /\ (inboundPacket = "None"
        \/ /\ inboundPacket \in {"KexInit"}
              /\ (~initialNewKeysActive \/ inboundTransportValid)
       )
    /\ state' = "Disconnected"
    /\ previousState' = state
    /\ history' = history
    /\ event' = "UnexpectedKexInit"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = (origin' = "ParsedPacket")
    /\ effects' = {"Disconnect", "SendProtocolError"}
    /\ rekeying' = FALSE
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = FALSE
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = FALSE
    /\ transcriptVerified' = FALSE
    /\ transportKeysVerified' = FALSE
    /\ lastPacketDisposition' = IF inboundPacket = "None" THEN "Client" ELSE "Accepted"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"]
    /\ channelEffects' = {}

PacketTransitionEnabled ==
    \/ /\ state \in {"Authenticating"}
       /\ inboundPacket \in {"UserauthFailure"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticating"}
       /\ inboundPacket \in {"UserauthSuccess"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated"}
       /\ inboundPacket \in {"ConnectionPacket", "ClientConnectionPacket"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticating"}
       /\ inboundPacket \in {"UserauthMethodSpecific"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
       /\ inboundPacket \in {"ConnectionPacket"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady"}
       /\ inboundPacket \in {"ExtInfo"}
       /\ inboundTransportValid
    \/ /\ state \in {"WaitService"}
       /\ inboundPacket \in {"ExtInfo"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
       /\ inboundPacket \in {"Disconnect"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"Authenticated"}
       /\ inboundPacket \in {"ChannelRequestReply"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated"}
       /\ inboundPacket \in {"ChannelOpenReply"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated"}
       /\ inboundPacket \in {"ChannelOpenReply"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated"}
       /\ inboundPacket \in {"ChannelRequestReply"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
       /\ inboundPacket \in {"Debug"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"Authenticated"}
       /\ inboundPacket \in {"GlobalRequest"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticated", "Authenticating", "AuthenticationReady", "Unconnected", "WaitKex", "WaitKexDhGexInit", "WaitKexInit", "WaitNewKeys", "WaitService", "WaitVersion"}
       /\ inboundPacket \in {"Ignore"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitNewKeys"}
       /\ inboundPacket \in {"NewKeys"}
       /\ ~(rekeying)
       /\ (~initialNewKeysActive \/ inboundTransportValid)
       /\ (~EnforceKexProofVerification \/ hostKeyPossessionVerified)
       /\ (~EnforceKexProofVerification \/ transcriptVerified)
    \/ /\ state \in {"WaitKexInit"}
       /\ inboundPacket \in {"KexInit"}
       /\ ~(rekeying)
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKexInit"}
       /\ inboundPacket \in {"KexInit"}
       /\ (~(rekeying)) /\ (~(nonKexBeforeInitialKexInit))
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKex"}
       /\ inboundPacket \in {"KexGexGroup"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKexDhGexInit"}
       /\ inboundPacket \in {"KexReply"}
       /\ (~EnforceKexProofVerification \/ inboundHostSignatureValid)
       /\ (~EnforceKexProofVerification \/ inboundTranscriptMatches)
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKex"}
       /\ inboundPacket \in {"KexReply"}
       /\ (~EnforceKexProofVerification \/ inboundHostSignatureValid)
       /\ (~EnforceKexProofVerification \/ inboundTranscriptMatches)
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKex"}
       /\ inboundPacket \in {"KexReply"}
       /\ (~EnforceKexProofVerification \/ inboundHostSignatureValid)
       /\ (~EnforceKexProofVerification \/ inboundTranscriptMatches)
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKexInit"}
       /\ inboundPacket \in {"KexInit"}
       /\ rekeying
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitNewKeys"}
       /\ inboundPacket \in {"NewKeys"}
       /\ rekeying
       /\ (~initialNewKeysActive \/ inboundTransportValid)
       /\ (~EnforceKexProofVerification \/ hostKeyPossessionVerified)
       /\ (~EnforceKexProofVerification \/ transcriptVerified)
    \/ /\ state \in {"WaitService"}
       /\ inboundPacket \in {"ServiceAccept"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticating"}
       /\ inboundPacket \in {"UserauthBanner"}
       /\ inboundTransportValid
    \/ /\ state \in {"AuthenticationReady"}
       /\ inboundPacket \in {"UserauthBanner"}
       /\ inboundTransportValid
    \/ /\ state \in {"Authenticating"}
       /\ inboundPacket \in {"UserauthMethodSpecific"}
       /\ inboundTransportValid
    \/ /\ state \in {"WaitKexInit"}
       /\ inboundPacket \in {"KexInit"}
       /\ (~(rekeying)) /\ (nonKexBeforeInitialKexInit)
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKex"}
       /\ inboundPacket \in {"KexInit"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitKexDhGexInit"}
       /\ inboundPacket \in {"KexInit"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)
    \/ /\ state \in {"WaitNewKeys"}
       /\ inboundPacket \in {"KexInit"}
       /\ (~initialNewKeysActive \/ inboundTransportValid)

HostilePacketFatal ==
    \/ /\ strictKex /\ ~rekeying /\ state \in KexStates
       /\ ~PacketTransitionEnabled
    \/ /\ inboundPacket = "KexInit"
       /\ state \in {"WaitKex", "WaitKexDhGexInit", "WaitNewKeys"}
    \/ /\ inboundPacket = "KexReply"
       /\ (~inboundHostSignatureValid \/ ~inboundTranscriptMatches)
    \/ /\ initialNewKeysActive /\ ~inboundTransportValid

RejectHostilePacket ==
    /\ inboundPacket # "None"
    /\ ~PacketTransitionEnabled
    /\ state' = IF HostilePacketFatal THEN "Disconnected" ELSE state
    /\ previousState' = state
    /\ history' = history
    /\ event' = "HostilePacketRejected"
    /\ origin' = "ParsedPacket"
    /\ packetWasParsed' = TRUE
    /\ effects' = IF HostilePacketFatal THEN {"Disconnect", "SendProtocolError"} ELSE {"SendUnimplemented"}
    /\ rekeying' = IF HostilePacketFatal THEN FALSE ELSE rekeying
    /\ strictKex' = strictKex
    /\ nonKexBeforeInitialKexInit' = nonKexBeforeInitialKexInit
    /\ authenticationEstablished' = authenticationEstablished
    /\ initialNewKeysActive' = initialNewKeysActive
    /\ authRequestPending' = IF HostilePacketFatal THEN FALSE ELSE authRequestPending
    /\ previousAuthRequestPending' = authRequestPending
    /\ inboundPacket' = "None"
    /\ lastInboundPacket' = inboundPacket
    /\ inboundTranscriptMatches' = inboundTranscriptMatches
    /\ inboundHostSignatureValid' = inboundHostSignatureValid
    /\ inboundTransportValid' = inboundTransportValid
    /\ hostKeyPossessionVerified' = IF HostilePacketFatal THEN FALSE ELSE hostKeyPossessionVerified
    /\ transcriptVerified' = IF HostilePacketFatal THEN FALSE ELSE transcriptVerified
    /\ transportKeysVerified' = IF HostilePacketFatal THEN FALSE ELSE transportKeysVerified
    /\ lastPacketDisposition' = IF HostilePacketFatal THEN "Disconnected" ELSE "Unimplemented"
    /\ previousChannels' = channels
    /\ activeChannel' = 0
    /\ channelEvent' = "None"
    /\ channelOrigin' = "None"
    /\ channels' = IF HostilePacketFatal THEN [c \in ChannelIDs |-> IF channels[c] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"] ELSE channels
    /\ channelEffects' = {}

HostileEnvironmentNext ==
    /\ EnableHostileEnvironment
    /\ inboundPacket = "None"
    /\ inboundPacket' \in PacketClasses
    /\ inboundTranscriptMatches' \in BOOLEAN
    /\ inboundHostSignatureValid' \in BOOLEAN
    /\ (inboundHostSignatureValid' => AdversaryOwnsHostKey)
    /\ inboundTransportValid' \in BOOLEAN
    /\ (inboundTransportValid' => AdversaryOwnsHostKey /\ transportKeysVerified)
    /\ UNCHANGED <<state, previousState, history, event, origin, packetWasParsed, effects, rekeying, strictKex, nonKexBeforeInitialKexInit, authenticationEstablished, initialNewKeysActive, authRequestPending, previousAuthRequestPending, lastInboundPacket, hostKeyPossessionVerified, transcriptVerified, transportKeysVerified, lastPacketDisposition, previousChannels, activeChannel, channelEvent, channelOrigin, channels, channelEffects>>

ClientNext ==
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
    \/ RECEIVE_INITIAL_NON_STRICT_KEX_INIT
    \/ RECEIVE_INITIAL_STRICT_KEX_INIT
    \/ RECEIVE_KEX_DH_GEX_GROUP
    \/ RECEIVE_KEX_DH_GEX_REPLY
    \/ RECEIVE_KEX_DH_REPLY
    \/ RECEIVE_KEX_ECDH_REPLY
    \/ RECEIVE_REKEY_KEX_INIT
    \/ RECEIVE_REKEY_NEW_KEYS
    \/ RECEIVE_SERVICE_ACCEPT
    \/ RECEIVE_USERAUTH_BANNER_AUTHENTICATING
    \/ RECEIVE_USERAUTH_BANNER_READY
    \/ RECEIVE_USERAUTH_INFO_REQUEST
    \/ RECEIVE_VERSION
    \/ RECORD_NON_KEX_BEFORE_INITIAL_KEX_INIT
    \/ REJECT_NON_KEX_WAIT_KEX
    \/ REJECT_NON_KEX_WAIT_KEX_DH_GEX_INIT
    \/ REJECT_NON_KEX_WAIT_NEW_KEYS
    \/ REJECT_STRICT_KEX_INIT_NOT_FIRST
    \/ REKEY_STARTED
    \/ REPEAT_BEGIN_AUTHENTICATION
    \/ SEND_CHANNEL_REQUEST
    \/ UNEXPECTED_KEX_INIT_WAIT_KEX
    \/ UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT
    \/ UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS
    \/ AttemptChannelOperation
    \/ RejectHostilePacket

Next == ClientNext \/ HostileEnvironmentNext

Spec == Init /\ [][Next]_vars
====
