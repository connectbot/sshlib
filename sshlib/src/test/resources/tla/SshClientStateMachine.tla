---- MODULE SshClientStateMachine ----
EXTENDS SshClientStateMachineGenerated

AuthenticatedOnlyEffects == {
    "ReceiveChannelFailure",
    "ReceiveChannelOpenConfirmation",
    "ReceiveChannelOpenFailure",
    "ReceiveChannelSuccess",
    "ReceiveGlobalRequest",
    "SendChannelOpen",
    "SendChannelRequest"
}

AuthenticatedOnlyEvents == {
    "AuthorizeAuthenticatedPacket",
    "OpenChannel",
    "ReceiveChannelFailure",
    "ReceiveChannelOpenConfirmation",
    "ReceiveChannelOpenFailure",
    "ReceiveChannelSuccess",
    "ReceiveGlobalRequest",
    "SendChannelRequest"
}

AuthenticationEstablishedStates ==
    {"Authenticated", "Disconnected"} \cup KexStates

HigherLayerOutboundEffects == {
    "SendChannelOpen",
    "SendChannelRequest",
    "SendServiceRequest",
    "SendUserauthRequest"
}

AuthenticationRequestEvents ==
    {"BeginAuthentication"}

TypeOK ==
    /\ state \in States
    /\ previousState \in States
    /\ history \in PostAuthenticatedStates
    /\ event \in Events \cup {"None"}
    /\ origin \in Origins
    /\ packetWasParsed \in BOOLEAN
    /\ effects \subseteq Effects
    /\ rekeying \in BOOLEAN
    /\ strictKex \in BOOLEAN
    /\ nonKexBeforeInitialKexInit \in BOOLEAN
    /\ authenticationEstablished \in BOOLEAN
    /\ initialNewKeysActive \in BOOLEAN
    /\ authRequestPending \in BOOLEAN
    /\ previousAuthRequestPending \in BOOLEAN
    /\ EnableHostileEnvironment \in BOOLEAN
    /\ AdversaryOwnsHostKey \in BOOLEAN
    /\ EnforceKexProofVerification \in BOOLEAN
    /\ inboundPacket \in PacketClasses \cup {"None"}
    /\ lastInboundPacket \in PacketClasses \cup {"None"}
    /\ inboundTranscriptMatches \in BOOLEAN
    /\ inboundHostSignatureValid \in BOOLEAN
    /\ inboundTransportValid \in BOOLEAN
    /\ hostKeyPossessionVerified \in BOOLEAN
    /\ transcriptVerified \in BOOLEAN
    /\ transportKeysVerified \in BOOLEAN
    /\ lastPacketDisposition \in PacketDispositions
    /\ MaxChannels \in Nat \ {0}
    /\ channels \in [ChannelIDs -> ChannelStates]
    /\ previousChannels \in [ChannelIDs -> ChannelStates]
    /\ activeChannel \in ChannelAttemptIDs
    /\ channelEvent \in ChannelEvents \cup {"None"}
    /\ channelOrigin \in ChannelOrigins \cup {"None"}
    /\ channelEffects \subseteq ChannelEffectSet

NoInvalidChannelSideEffects ==
    channelEffects # {} =>
        /\ activeChannel \in ChannelIDs
        /\ ChannelOperationAllowed(
               authenticationEstablished,
               state,
               previousChannels[activeChannel],
               channelEvent
           )
        /\ channelEffects = ChannelEffectsFor(
               previousChannels[activeChannel],
               channelEvent
           )
        /\ channelOrigin = ChannelOriginFor(channelEvent)

ChannelIsolation ==
    activeChannel \in ChannelIDs =>
        \A other \in ChannelIDs \ {activeChannel} :
            channels[other] = previousChannels[other]

GlobalOperationsPreserveChannels ==
    activeChannel = 0 /\ "Disconnect" \notin effects =>
        channels = previousChannels

GlobalChannelMutationIsDisconnectCascade ==
    activeChannel = 0 /\ channels # previousChannels =>
        /\ "Disconnect" \in effects
        /\ state = "Disconnected"
        /\ \A channel \in ChannelIDs :
            channels[channel] =
                IF previousChannels[channel] = "Unallocated" THEN "Unallocated" ELSE "CLOSED"

DisconnectedClosesChannels ==
    state = "Disconnected" =>
        \A channel \in ChannelIDs :
            channels[channel] \in {"Unallocated", "CLOSED"}

NoChannelsBeforeAuthentication ==
    ~authenticationEstablished =>
        \A channel \in ChannelIDs : channels[channel] = "Unallocated"

RekeyTransitionsPreserveChannels ==
    activeChannel = 0 /\
        (event = "RekeyStarted" \/ rekeying \/ "RekeyComplete" \in effects) =>
            channels = previousChannels

AuthenticatedRekeyChannelGuardsRemainEnabled ==
    authenticationEstablished /\ state \in KexStates =>
        \A channel \in ChannelIDs :
            \A operation \in ChannelEvents :
                ChannelTransitionDefined(channels[channel], operation) =>
                    ChannelOperationAllowed(
                        authenticationEstablished,
                        state,
                        channels[channel],
                        operation
                    )

ModelView ==
    <<state,
      previousState,
      history,
      event,
      origin,
      packetWasParsed,
      effects,
      rekeying,
      strictKex,
      nonKexBeforeInitialKexInit,
      authenticationEstablished,
      initialNewKeysActive,
      authRequestPending,
      previousAuthRequestPending,
      inboundPacket,
      lastInboundPacket,
      inboundTranscriptMatches,
      inboundHostSignatureValid,
      inboundTransportValid,
      hostKeyPossessionVerified,
      transcriptVerified,
      transportKeysVerified,
      lastPacketDisposition,
      channels,
      NoInvalidChannelSideEffects,
      ChannelIsolation>>

AuthenticationStateIsMonotonic ==
    authenticationEstablished => state \in AuthenticationEstablishedStates

AuthenticationNeverDowngrades ==
    [] (authenticationEstablished => [] authenticationEstablished)

DisconnectedIsTerminal ==
    [] (state = "Disconnected" => [] (state = "Disconnected"))

NoAuthenticatedEffectsBeforeAuthentication ==
    previousState # "Authenticated" => effects \cap AuthenticatedOnlyEffects = {}

AuthenticatedEventsAreGuarded ==
    event \in AuthenticatedOnlyEvents => previousState = "Authenticated"

ParsedPacketProvenance ==
    origin = "ParsedPacket" => packetWasParsed

NoForgedPacketProvenance ==
    packetWasParsed => origin = "ParsedPacket"

AuthenticationSuccessIsGuarded ==
    event = "AuthenticationSuccess" =>
        /\ previousState = "Authenticating"
        /\ state = "Authenticated"

AuthenticationPacketIsGuarded ==
    event = "AuthorizeAuthenticationPacket" => previousState = "Authenticating"

RekeyStartIsWellFormed ==
    event = "RekeyStarted" =>
        /\ previousState \in PostAuthenticatedStates
        /\ state = "WaitKexInit"
        /\ history = previousState
        /\ rekeying

RekeyingHasSavedPostAuthenticationState ==
    rekeying =>
        /\ state \in KexStates
        /\ history \in PostAuthenticatedStates

RekeyCompletionIsWellFormed ==
    "RekeyComplete" \in effects =>
        /\ event = "ReceiveNewKeys"
        /\ previousState = "WaitNewKeys"
        /\ state = history
        /\ ~rekeying

NoHigherLayerPacketsSentDuringKex ==
    state \in KexStates => effects \cap HigherLayerOutboundEffects = {}

AuthenticationRequestIsGuarded ==
    event \in AuthenticationRequestEvents =>
        /\ previousState \in {"AuthenticationReady", "Authenticating"}
        /\ ~authenticationEstablished
        /\ ~previousAuthRequestPending
        /\ authRequestPending

AuthenticationRequestResponseClearsPending ==
    event \in {"AuthenticationSuccess", "AuthenticationFailure", "AuthorizeAuthenticationPacket"} =>
        ~authRequestPending

KexEventsAreStrictlySequenced ==
    /\ event \in {"ReceiveInitialStrictKexInit", "ReceiveInitialNonStrictKexInit", "ReceiveRekeyKexInit"} /\
        "Disconnect" \notin effects =>
        /\ previousState = "WaitKexInit"
        /\ state = "WaitKex"
        /\ "SendKexExchangeInit" \in effects
    /\ event \in {"ReceiveKex.DhReply", "ReceiveKex.EcdhReply"} =>
        /\ previousState = "WaitKex"
        /\ state = "WaitNewKeys"
        /\ "SendNewKeys" \in effects
        /\ "ActivateOutboundProtection" \in effects
        /\ (strictKex => "ResetOutboundSequence" \in effects)
    /\ event = "ReceiveKex.DhGexGroup" =>
        /\ previousState = "WaitKex"
        /\ state = "WaitKexDhGexInit"
        /\ "SendKexDhGexInit" \in effects
    /\ event = "ReceiveKex.DhGexReply" =>
        /\ previousState = "WaitKexDhGexInit"
        /\ state = "WaitNewKeys"
        /\ "SendNewKeys" \in effects
        /\ "ActivateOutboundProtection" \in effects
        /\ (strictKex => "ResetOutboundSequence" \in effects)
    /\ event = "ReceiveNewKeys" =>
        /\ previousState = "WaitNewKeys"
        /\ "ActivateEncryption" \in effects
        /\ "ActivateInboundProtection" \in effects
        /\ (strictKex => "ResetInboundSequence" \in effects)

StrictKexProtectionSwitchesResetSequenceNumbers ==
    strictKex =>
        /\ ("ActivateOutboundProtection" \in effects => "ResetOutboundSequence" \in effects)
        /\ ("ActivateInboundProtection" \in effects => "ResetInboundSequence" \in effects)

StrictKexIsSticky ==
    [] (strictKex => [] strictKex)

StrictInitialKexRejectsNonKexPackets ==
    event = "ReceiveNonKexPacket" /\ previousState \in {"WaitKex", "WaitKexDhGexInit", "WaitNewKeys"} =>
        /\ strictKex
        /\ state = "Disconnected"
        /\ "SendProtocolError" \in effects
        /\ "Disconnect" \in effects

StrictKexInitMustBeFirst ==
    event = "ReceiveInitialStrictKexInit" /\ "Disconnect" \in effects =>
        /\ strictKex
        /\ nonKexBeforeInitialKexInit
        /\ previousState = "WaitKexInit"
        /\ state = "Disconnected"

AcceptedInitialKexPacketOrderClearsHistory ==
    event \in {"ReceiveInitialStrictKexInit", "ReceiveInitialNonStrictKexInit"} /\ "Disconnect" \notin effects =>
        /\ state = "WaitKex"
        /\ ~nonKexBeforeInitialKexInit

UserAuthenticationRequiresInitialNewKeys ==
    event = "BeginAuthentication" \/ "StartAuthentication" \in effects \/ "SendUserauthRequest" \in effects =>
        initialNewKeysActive

UnexpectedKexInitIsFatal ==
    event = "UnexpectedKexInit" =>
        /\ previousState \in {"WaitKex", "WaitKexDhGexInit", "WaitNewKeys"}
        /\ state = "Disconnected"
        /\ "SendProtocolError" \in effects
        /\ "Disconnect" \in effects

HostileKexReplyRequiresPossessionProof ==
    inboundPacket = "None" /\ lastPacketDisposition = "Accepted" /\
        event \in {"ReceiveKex.DhReply", "ReceiveKex.EcdhReply", "ReceiveKex.DhGexReply"} =>
            /\ inboundHostSignatureValid
            /\ inboundTranscriptMatches
            /\ hostKeyPossessionVerified
            /\ transcriptVerified

NewKeysRequiresVerifiedTranscript ==
    event = "ReceiveNewKeys" =>
        /\ hostKeyPossessionVerified
        /\ transcriptVerified
        /\ transportKeysVerified

ProtectedHostilePacketsRequireTransportAuthentication ==
    inboundPacket = "None" /\ lastPacketDisposition = "Accepted" /\
        event \in {
            "ReceiveServiceAccept",
            "AuthenticationSuccess",
            "AuthenticationFailure",
            "AuthorizeAuthenticationPacket",
            "AuthorizeAuthenticatedPacket",
            "AuthorizeConnectionPacket",
            "AuthorizeExtInfo",
            "ReceiveGlobalRequest",
            "ReceiveChannelOpenConfirmation",
            "ReceiveChannelOpenFailure",
            "ReceiveChannelSuccess",
            "ReceiveChannelFailure"
        } => inboundTransportValid

AuthenticationRequiresVerifiedTransport ==
    authenticationEstablished /\ state # "Disconnected" => transportKeysVerified

HostileClientRolePacketsNeverAdvance ==
    inboundPacket = "None" /\ lastPacketDisposition = "Accepted" =>
        lastInboundPacket \notin {
            "ClientKexInit",
            "ClientServiceRequest",
            "ClientUserauthRequest"
        }

RejectedHostilePacketsDoNotEstablishSecurity ==
    inboundPacket = "None" /\ lastPacketDisposition \in {"Unimplemented", "Disconnected"} =>
        /\ event = "HostilePacketRejected"
        /\ (lastPacketDisposition = "Unimplemented" =>
                /\ state = previousState
                /\ effects = {"SendUnimplemented"})

\* Hostile profiles focus on connection-level packet ordering. The baseline
\* configuration separately explores the full two-channel product state.
HostileSecurityActionConstraint == channelEvent' = "None"

====
