# SSH Client Library & Protocol Parser

An SSH client library built with Kotlin coroutines and Kaitai Struct. Connects
to SSH servers, authenticates, and provides interactive shell sessions with
channel data I/O. Protocol parsing uses declarative Kaitai Struct specifications
that auto-generate code from `.ksy` definitions. The internal state machine is
defined in KStateMachine for easier reasoning of possible state transitions.

## Features

- **SSH Client**: Connect, authenticate, open shell sessions, read/write data
- **Protocol Parsing**: Complete SSH wire protocol coverage (RFCs 4250-4256,
  4419, 5656, 8308, 8709, 8731, 9142)
- **Key Exchange**: diffie-hellman-group14-sha256, diffie-hellman-group14-sha1
- **Encryption**: AES-128-CTR, AES-256-CTR with HMAC-SHA2-256/512
- **Authentication**: Password
- **Channel I/O**: Interactive shells with PTY, stdout/stderr streams, flow
  control
- **Transport**: Pluggable transport layer (TCP via Ktor, or custom)
- **CLI Client**: Interactive terminal client included in testapp module

## Quick Start

### Build

```bash
./gradlew build
```

### Use the CLI Client

```bash
./gradlew :testapp:installDist
./testapp/build/install/testapp/bin/testapp user@host
./testapp/build/install/testapp/bin/testapp user@host -p 2222
./testapp/build/install/testapp/bin/testapp -d user@host  # debug logging
```

### Library API

```kotlin
val client = SshClient("example.com", 22)
client.connect()
client.authenticatePassword("user", "pass")

val session = client.openSession()
session.requestPty()
session.requestShell()

// Read/write
session.write("ls\n".toByteArray())
val output = session.read()  // ByteArray? (null on EOF)

// Or use coroutine channels directly
session.stdout  // ReceiveChannel<ByteArray>
session.stderr  // ReceiveChannel<ByteArray>

// Clean up
session.close()
client.disconnect()
```

### Parse SSH Messages

```java
ByteBufferKaitaiStream stream = new ByteBufferKaitaiStream(bytes);
Ssh.IdBanner banner = new Ssh.IdBanner(stream);
banner._read();
System.out.println("Version: " + banner.protoVersion());

Ssh.UnencryptedPacket packet = new Ssh.UnencryptedPacket(stream);
packet._read();
switch (packet.payload().messageType()) {
    case SSH_MSG_KEXINIT:
        Ssh.SshMsgKexinit kexinit = (Ssh.SshMsgKexinit) packet.payload().body();
        System.out.println("KEX algorithms: " + kexinit.kexAlgorithms());
        break;
}
```

## Project Structure

```
ssh-proto/
├── sshlib/                      # SSH library module
│   └── src/main/
│       ├── kotlin/org/connectbot/sshlib/
│       │   ├── SshClient.kt           # Public async API
│       │   ├── SshSession.kt          # Session interface (read/write/PTY)
│       │   ├── SshClientConfig.kt     # Configuration DSL
│       │   ├── blocking/              # Java-compatible blocking wrapper
│       │   ├── client/                # SshConnection, SessionChannel
│       │   ├── crypto/                # AES-CTR, HMAC, DH, key derivation
│       │   ├── transport/             # Transport interface, Ktor TCP, PacketIO
│       │   └── struct/                # State machine (KStateMachine)
│       └── resources/kaitai/          # .ksy protocol definitions
└── testapp/                     # CLI client and integration tests
    └── src/main/kotlin/               # Interactive SSH CLI
```

## Current Limitations

- No public key authentication
- No host key verification
- No ECDH/Curve25519 key exchange
- No SFTP, port forwarding, or agent forwarding
- Client-only (no server implementation)

## License

Apache License 2.0 - See LICENSE file

## Copyright

Copyright 2019-2025, [Kenny Root](https://github.com/kruton/)
