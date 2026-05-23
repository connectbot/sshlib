# Changelog

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

[0.3.0]: https://github.com/connectbot/cbssh/compare/v0.2.1...v0.3.0
