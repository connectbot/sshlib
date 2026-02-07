# Module protocol

This module contains the Kaitai Struct definitions for SSH protocol messages. It is used to generate the binary parsing and serialization code for the SSH protocol.

## Getting Started

The main entry point for the protocol is the `Ssh` class (generated from `ssh.ksy`).

To use it in your project, add the dependency:

```kotlin
implementation("org.connectbot:protocol:VERSION")
```

The protocol definitions cover RFC 4253 and various extensions, including OpenSSH specific messages.
