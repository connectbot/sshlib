# FIDO2 / Security Key Authentication

The library supports authentication with `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` keys.

## Overview

This library does **not** include a CTAP2 transport (USB-HID, NFC, BLE). Callers are responsible for providing their own FIDO2 stack and surfacing the resulting assertion through [`AuthHandler.onSignatureRequest`](../sshlib/src/main/kotlin/org/connectbot/sshlib/AuthHandler.kt).

The helpers in `org.connectbot.sshlib.sk` cover the SSH wire-format bits so
callers don't have to implement OpenSSH's `PROTOCOL.u2f` themselves.

## Implementation Example

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

val client = SshClient("server.example.com", hostKeyVerifier = myVerifier)
client.connect()
val result = client.authenticate("user", SkAuthHandler(...))
```

## ECDSA P-256 Keys

For ECDSA-P256 keys, pass `SkAlgorithm.ECDSA_P256` and supply the DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` signature that CTAP2 returns. `SkSignatureBlob.pack()` converts it to OpenSSH's `mpint r || mpint s` form internally.

## Public Key Decoding

Use `SkPublicKeyDecoder` to parse public-key blobs that arrive in OpenSSH-format SK files.

## Out of Scope

The following are **not** handled by this library:
- CTAP2 transport (USB-HID, NFC, BLE).
- Credential creation (`ssh-keygen -t *-sk` equivalent).
- Parsing `ssh-keygen`'s OpenSSH-format SK private-key files. (The library decodes the SK *public-key blob*; the surrounding OpenSSH private-key envelope is the caller's responsibility.)
