# AGENTS.md

This file provides orientation for coding agents working in this repository.
For deeper reference, see the linked files below.

## Project Overview

This project is an **SSH client library** built with Kotlin coroutines, Kaitai Struct, and KStateMachine.

**What this project provides**:
- SSH protocol message parsing/serialization (RFCs 4250-4256, 4419, 5656, 8308, 8709, 8731, 9142)
- Async Kotlin SSH client API (`SshClient`, `SshSession`)
- Key exchange: curve25519, ML-KEM hybrid, ECDH (nistp256/384/521), DH group14/16/18, DH group-exchange
- Encryption: chacha20-poly1305, AES-GCM, AES-CTR, AES-CBC, 3DES-CBC
- MACs: HMAC-SHA2-256/512, HMAC-SHA1 (with ETM variants)
- Host key verification: Ed25519, Ed448, ECDSA (nistp256/384/521), RSA (SHA-256, SHA-512)
- Password, keyboard-interactive, and public key authentication
- Interactive shell sessions with PTY support
- SFTP file transfer (draft-ietf-secsh-filexfer)
- Port forwarding: local, remote, dynamic (SOCKS5)
- Agent forwarding with session binding
- Pluggable transport layer (TCP via Ktor, or custom)

**Current limitations**:
- Client-only (no server implementation)

## Guiding Principles

1. **Minimize hand-written parsing** — All SSH wire protocol messages are defined in Kaitai Struct (`.ksy` files). Do not write manual byte-level parsers; add or extend `.ksy` definitions instead.
2. **Explicit, inspectable state machine** — Connection lifecycle states and transitions live in KStateMachine configuration. State and transition logic must be readable from the KStateMachine setup; do not encode implicit state in ad-hoc flags or conditionals outside the state machine.

## Module Overview

This is a **multi-module Gradle project**:

- **`:protocol`** — Internal. Kaitai Struct code generation from `.ksy` definitions. Generates Java classes in `org.connectbot.sshlib.protocol`. Hidden from library consumers via `implementation` dependency.
- **`:sshlib`** — Core SSH library. Public API: `SshClient`, `SshSession`, `SshClientConfig`, `SftpClient`, `BlockingSshClient`. API tracked in `sshlib/api.txt` via Metalava.
- **`:testapp`** — Interactive CLI client for manual testing.

## Build Commands

```bash
./gradlew :sshlib:compileKotlin          # fast compile check
./gradlew build                          # compile + test all modules
./gradlew :sshlib:build                  # compile + test library only
./gradlew :sshlib:test                   # unit and integration tests (requires Docker)
./gradlew :protocol:kaitai               # regenerate Kaitai Struct classes
./gradlew :sshlib:metalavaGenerateSignature   # update api.txt
./gradlew :sshlib:metalavaCheckCompatibility  # verify against api.txt
./gradlew :testapp:installDist           # build CLI client
```

Run a single test class:
```bash
./gradlew :sshlib:test --tests "org.connectbot.sshlib.crypto.AlgorithmsTest"
```

## Development Workflow

1. Modify `.ksy` files in `:protocol` if changing the wire protocol.
2. Run `./gradlew build` to regenerate classes and verify the whole project.
3. Run `./gradlew :sshlib:metalavaGenerateSignature` if you intentionally changed the public API.
4. Run `./gradlew :sshlib:test` to run unit and integration tests (requires Docker).

## Reference

- **[Internal implementation](docs/agents/internals.md)** — architecture, Kaitai Struct usage, concurrency rules, coding guidelines
- **[Integration testing](docs/agents/testing.md)** — test servers, compatibility quirks, test keys
- **[README.md](README.md)** — user-facing project overview and API examples
- **[sshlib/api.txt](sshlib/api.txt)** — tracked public API signature
