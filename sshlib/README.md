# Module sshlib-ktx

A high-level SSH client library for Kotlin and Java, built with coroutines and modern cryptography.

## Getting Started

### Kotlin

For Kotlin projects, use `SshClient` which provides a coroutine-based API.

```kotlin
val client = SshClient("example.com")
if (client.connect()) {
    if (client.authenticatePassword("user", "password")) {
        val session = client.openSession()
        session?.requestShell()
        // ...
        session?.close()
    }
    client.disconnect()
}
```

### Java

For Java projects, use `BlockingSshClient` which provides a traditional blocking API.

```java
BlockingSshClient client = new BlockingSshClient("example.com", 22, hostKeyVerifier);
if (client.connect()) {
    if (client.authenticatePassword("user", "password")) {
        SshSession session = client.openSession();
        // ...
        session.close();
    }
    client.disconnect();
}
```

## Features

- Modern cryptography (Ed25519, ChaCha20-Poly1305, etc.)
- Post-quantum cryptography support (ML-KEM)
- Coroutine-based async API
- Easy to use high-level abstractions
