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
    /\ authenticationEstablished \in BOOLEAN
    /\ initialNewKeysActive \in BOOLEAN
    /\ authRequestPending \in BOOLEAN
    /\ previousAuthRequestPending \in BOOLEAN
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

DisconnectedClosesChannels ==
    state = "Disconnected" =>
        \A channel \in ChannelIDs :
            channels[channel] \in {"Unallocated", "CLOSED"}

ModelView ==
    <<state,
      previousState,
      history,
      event,
      origin,
      packetWasParsed,
      effects,
      rekeying,
      authenticationEstablished,
      initialNewKeysActive,
      authRequestPending,
      previousAuthRequestPending,
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
    /\ event = "ReceiveKexInit" =>
        /\ previousState = "WaitKexInit"
        /\ state = "WaitKex"
        /\ "SendKexExchangeInit" \in effects
    /\ event \in {"ReceiveKex.DhReply", "ReceiveKex.EcdhReply"} =>
        /\ previousState = "WaitKex"
        /\ state = "WaitNewKeys"
        /\ "SendNewKeys" \in effects
    /\ event = "ReceiveKex.DhGexGroup" =>
        /\ previousState = "WaitKex"
        /\ state = "WaitKexDhGexInit"
        /\ "SendKexDhGexInit" \in effects
    /\ event = "ReceiveKex.DhGexReply" =>
        /\ previousState = "WaitKexDhGexInit"
        /\ state = "WaitNewKeys"
        /\ "SendNewKeys" \in effects
    /\ event = "ReceiveNewKeys" =>
        /\ previousState = "WaitNewKeys"
        /\ "ActivateEncryption" \in effects

UserAuthenticationRequiresInitialNewKeys ==
    event = "BeginAuthentication" \/ "StartAuthentication" \in effects \/ "SendUserauthRequest" \in effects =>
        initialNewKeysActive

UnexpectedKexInitIsFatal ==
    event = "UnexpectedKexInit" =>
        /\ previousState \in {"WaitKex", "WaitKexDhGexInit", "WaitNewKeys"}
        /\ state = "Disconnected"
        /\ "SendProtocolError" \in effects
        /\ "Disconnect" \in effects

====
