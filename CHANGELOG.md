# Changelog

## [0.4.1][0.4.1]

Changes for library users since `0.4.0`.

### Changed

- Bound TLA+ Terrapin model to implementation and tightened up the SFTP model.

### Fixed

- Ensured channels are unregistered and old channels are closed in the registry.

## [0.4.0][0.4.0]

Changes for library users since `0.3.1`.

### Added

- Added `SshSession.exitInfo` (`Deferred<SessionExit>`) to expose remote execution
  exit status (`SessionExit.Status`) and exit signal (`SessionExit.Signal`) details
  sent via `SSH_MSG_CHANNEL_REQUEST` `exit-status` and `exit-signal` messages.
- Added formal TLA+ specifications and model checking for verifying state machine
  transitions, channel isolation, and Terrapin attack mitigation.

### Changed

- Converted channel lifecycle management to explicit state machines using `KStateMachine`
  to support formal modeling and strict state separation.
- Updated default algorithm preference lists to prioritize modern cryptographic
  ciphers, key exchanges, and MACs.

### Fixed

- Enforced strict session binding (session ID and host key verification) for forwarded
  SSH agent signing requests.
- Implemented receive-window backpressure across channel types (session, port
  forwarding, and agent) to prevent window overflows.
- Bounded nested field sizes and entry counts during SFTP response decoding to
  prevent excessive memory allocation from malformed responses.
- Verified host-key proof signatures prior to trusting host keys during key exchange.
- Validated parameter boundaries and key lengths during Diffie-Hellman group exchange.
- Directionally isolated rekeying state transitions to handle inbound and outbound
  key exchange independently.
- Decoupled SSH agent response handling from the main packet loop to prevent connection
  deadlocks.
- Hardened connection tear-down to ensure transport closure occurs cleanly and only
  once under concurrent close requests.
- Ensured `ssh-rsa` algorithm wishlist selections are honored when explicitly specified.
- Switched outbound SSH packet padding generation to cryptographically secure random values.
- Fixed passphrase encryption when exporting Ed25519 private keys to PKCS#8 format.

## [0.3.1][0.3.1]

Changes for library users since `0.3.0`.

### Fixed

- Restricted maximum length constraints on SSH agent messages and packet payload fields
  to prevent excessive memory allocation when processing untrusted wire data
  (GHSA-ch3q-cw5r-f4hg).
- Hardened DER length and integer parsing for ASN.1 private keys to prevent integer
  overflow and excessive memory allocation (GHSA-vc8p-8pxg-rfwg).

## [0.3.0][0.3.0]

Changes for library users since `0.2.1`.

### Added

- Added FIDO2 / Security Key authentication helpers for
  `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` keys
  in the new `org.connectbot.sshlib.sk` package. The library handles the SSH
  wire-format pieces while callers provide their own CTAP2 transport.
- Added `AuthHandler.onBanner(message)` so applications can display
  `SSH_MSG_USERAUTH_BANNER` messages during authentication.
- Added `KtorTcpTransport.getLocalAddress()` to expose the local socket address
  assigned to a connected TCP transport.
- Added `docs/ALGORITHMS.md` with the complete supported algorithm list and
  `docs/SK_AUTH.md` with Security Key authentication guidance.

### Changed

- `SshClient(...)` and `BlockingSshClient(...)` convenience constructors now
  require an explicit `HostKeyVerifier`. This makes host-key verification a
  required caller decision instead of allowing a convenience constructor that
  could not build a valid `SshClientConfig`.
- `AuthHandler.onSignatureRequest()` is documented as a verbatim signature
  extension point for local private keys, SSH agents, and FIDO2 authenticators.

### Fixed

- Authentication banners are now delivered to callers during every authentication
  step instead of only being logged.
- `SshSigning.sign()` now rejects `sk-*` algorithms with an actionable error,
  since Security Key private material lives on the authenticator and must be
  signed through `AuthHandler.onSignatureRequest()`.
- Hardened host-key signature verification by requiring the signature algorithm
  to match the negotiated host-key algorithm.
- Hardened agent session-binding signature verification by requiring the
  signature algorithm to be compatible with the key type.
- Hardened key exchange and channel handling by rejecting all-zero ECDH shared
  secrets, invalid DH group-exchange parameters, channel-window overflows, and
  incoming channel data that exceeds the local receive window.
- Limited zlib decompression output per packet to reduce decompression-bomb
  denial-of-service risk.

[0.4.1]: https://github.com/connectbot/cbssh/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/connectbot/cbssh/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/connectbot/cbssh/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/connectbot/cbssh/compare/v0.2.1...v0.3.0
