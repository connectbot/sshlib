# ConnectBot SSH Client Library

This is ConnectBot SSH library built with Kotlin. Internally it uses coroutines,
protocol definition files, and a state machine to run the SSH protocol. It
currently connects to SSH servers, authenticates, and provide interactive shell
sessions.

The protocol parsing uses declarative Kaitai Struct specifications
that auto-generate code from `.ksy` definitions. The internal state machine is
defined in KStateMachine for clear separation of protocol states from the code
that runs in reaction to state changes.

## Features

- **SSH Client**: Connect, authenticate, open shell sessions, read/write data
- **Protocol Parsing**: Complete SSH wire protocol coverage (RFCs 4250-4256,
  4419, 5656, 8308, 8709, 8731, 9142)
- **Channel I/O**: Interactive shells with PTY, stdout/stderr streams, flow
  control
- **SFTP**: File transfer with full read/write/stat/directory operations
  ([draft-ietf-secsh-filexfer](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer))
- **Port Forwarding**: Local, remote, and dynamic (SOCKS5) port forwarding
- **Agent Forwarding**: Forward SSH agent requests with session binding support
- **Transport**: Pluggable transport layer (TCP via Ktor, or custom)

## Algorithm Support

The library supports a wide range of modern SSH algorithms, including:
- **Authentication**: `publickey` (including FIDO2/SK), `password`, `keyboard-interactive`
- **Host Keys**: Ed25519, Ed448, ECDSA, RSA (SHA-2)
- **Key Exchange**: ML-KEM hybrid, Curve25519, ECDH, DH group-exchange
- **Encryption**: ChaCha20-Poly1305, AES-GCM, AES-CTR
- **MACs**: HMAC-SHA2 (including ETM variants)

For a complete list of supported algorithms and their respective RFCs, see [docs/ALGORITHMS.md](docs/ALGORITHMS.md).

## Quick Start

### Build

```bash
./gradlew build
```

### Use the Test CLI Client

There is a "testapp" that allows you to try the library from a test client app.
You can use it by running the following commands:

```bash
./gradlew :testapp:installDist
./testapp/build/install/testapp/bin/testapp user@host
./testapp/build/install/testapp/bin/testapp user@host -p 2222

# Enable more debug logging:
./testapp/build/install/testapp/bin/testapp -d user@host
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

### SFTP File Transfer

```kotlin
val sftp = when (val result = client.openSftp()) {
    is SftpResult.Success -> result.value
    else -> error("Failed to open SFTP: $result")
}

try {
    // List a directory
    when (val result = sftp.listdir("/home/user")) {
        is SftpResult.Success -> result.value.forEach { println(it.filename) }
        is SftpResult.ServerError -> println("Server error: ${result.message}")
        else -> println("Error: $result")
    }

    // Read a file
    val handle = sftp.open("/home/user/file.txt", setOf(SftpOpenFlag.READ)).getOrThrow()
    val data = sftp.read(handle, 0L, 4096).getOrThrow()
    sftp.close(handle)
} finally {
    sftp.close()
}
```

### FIDO2 / Security Key Authentication

The library supports authentication with `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` keys, but it does **not** include a CTAP2
transport — callers bring their own FIDO2 stack (USB-HID, NFC, BLE) and surface
the resulting assertion through [`AuthHandler.onSignatureRequest`][auth-handler].
The helpers in `org.connectbot.sshlib.sk` cover the SSH wire-format bits so
callers don't have to implement OpenSSH's `PROTOCOL.u2f` themselves.

```kotlin
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.sk.SkAlgorithm
import org.connectbot.sshlib.sk.SkAuthHelpers
import org.connectbot.sshlib.sk.SkSignatureBlob

class SkAuthHandler(
    private val rawPublicKey: ByteArray,   // 32-byte Ed25519 pubkey from your stored SK
    private val application: String,       // RP id, e.g. "ssh:"
    private val credentialId: ByteArray,   // CTAP2 credential id
    private val ctap2: MyCtap2Stack,       // your CTAP2 transport
) : AuthHandler {
    override suspend fun onPublicKeysNeeded() = listOf(
        SkAuthHelpers.buildAuthPublicKey(SkAlgorithm.ED25519, rawPublicKey, application),
    )

    override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray {
        // The CTAP2 device hashes (clientDataHash) for us — just pass dataToSign through SHA-256.
        val assertion = ctap2.getAssertion(
            rpId = application,
            credentialId = credentialId,
            clientDataHash = sha256(dataToSign),
        )
        return SkSignatureBlob.pack(
            algorithm = SkAlgorithm.ED25519,
            rawSignature = assertion.signature,  // 64-byte raw Ed25519, or DER for ECDSA-P256
            flags = assertion.flags,             // 0x01 = UP, |0x04 if UV was tested
            counter = assertion.counter,
        )
    }

    override suspend fun onPasswordNeeded() = null
    override suspend fun onKeyboardInteractivePrompt(...) = null
}

val client = SshClient("server.example.com")
client.connect()
val result = client.authenticate("user", SkAuthHandler(...))
```

For ECDSA-P256 keys, pass `SkAlgorithm.ECDSA_P256` and supply the DER-encoded
`SEQUENCE { INTEGER r, INTEGER s }` signature that CTAP2 returns — `pack()`
converts it to OpenSSH's `mpint r || mpint s` form internally. Use
`SkPublicKeyDecoder` to parse public-key blobs that arrive in OpenSSH-format
SK files.

What's out of scope for this library:

- A CTAP2 transport (USB-HID, NFC, BLE).
- Credential creation (`ssh-keygen -t *-sk` equivalent).
- Parsing `ssh-keygen`'s OpenSSH-format SK private-key files. (The library
  decodes the SK *public-key blob*; the surrounding OpenSSH private-key
  envelope is the caller's responsibility.)

[auth-handler]: https://github.com/kruton/ssh-proto/blob/main/sshlib/src/main/kotlin/org/connectbot/sshlib/AuthHandler.kt

### SSH Agent Forwarding

Enable SSH agent forwarding to allow remote servers to use your keys:

```kotlin
// Implement an agent provider
class MyAgentProvider : AgentProvider {
    override suspend fun getIdentities(): List<AgentIdentity> {
        val keyBlob = loadPublicKeyBlob()
        return listOf(AgentIdentity(keyBlob, "my-key"))
    }

    override suspend fun signData(context: AgentSigningContext): ByteArray? {
        // Show approval UI to user with session context
        val approved = showSigningPrompt(
            "Remote server ${context.serverHostKey.toHex()} wants to use your key",
            "Session bound: ${context.isBound}"
        )

        return if (approved) {
            signWithPrivateKey(context.publicKeyBlob, context.dataToSign)
        } else {
            null  // Deny the request
        }
    }
}

// Enable agent forwarding
val client = SshClient("bastion.example.com")
client.connect()
client.authenticatePassword("user", "pass")
client.enableAgentForwarding(MyAgentProvider())

// Now remote servers can use your agent through forwarding
val session = client.openSession()
session.requestShell()
// When you SSH from bastion to another server, it can request signatures
```

## Compatibility Testing

The library is tested against multiple SSH server implementations using Docker
(via Testcontainers):

- **OpenSSH** 9.9p2 — full integration tests including port forwarding
- **AsyncSSH** (Python) — compatibility tests for ciphers, key exchange, MACs,
  and public key auth
- **Dropbear** — compatibility tests including ML-KEM post-quantum key exchange

Run integration tests with: `./gradlew :sshlib:test` (requires Docker).

## Current Limitations

- Client-only (no server implementation)

## License

Apache License 2.0 - See LICENSE file

## Copyright

Copyright 2019-2025, [Kenny Root](https://github.com/kruton/)
