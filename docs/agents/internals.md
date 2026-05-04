# Internal Implementation Reference

This file covers architecture details, protocol serialization, concurrency rules, and coding
guidelines for agents working on the internal implementation of the SSH library.

## Algorithm Registry (`Algorithms.kt`)

All supported cryptographic algorithms are declared in enum registries. **Visibility is strictly managed** to limit the public API.

- **`CipherEntry`**, **`MacEntry`**, **`KexEntry`**: Public enums for choosing algorithms, but their `create()` factory methods are `internal`.
- **`SignatureEntry`**: Public enum for host key algorithms. The underlying `algorithm` property is `internal`.
- **Interfaces**: `PacketMac`, `KexAlgorithm`, `PacketCipher`, `PacketAead`, `X25519Provider`, and `SshSignatureAlgorithm` are all `internal`.

**To add a new algorithm**: add an enum entry in `Algorithms.kt`. `SshConnection` and `SshClientConfig` consume the registries.

## Code Generation Pipeline

**Kaitai Struct Compiler**: Generates Java classes from `.ksy` protocol definitions.
- Module: `:protocol`
- Input: `protocol/src/main/resources/kaitai/*.ksy`
- Output: `protocol/build/generated/kaitai/org/connectbot/sshlib/protocol/`
- The `kaitai` task automatically runs before compilation.

## State Machine (`SshClientStateMachine.kt`)

Implements SSH client connection lifecycle using KStateMachine.
- **Internal Visibility**: The state machine and its `SshClientCallbacks` are `internal`.
- **Refactored SshConnection**: `SshConnection` no longer implements `SshClientCallbacks` publicly. It uses a private inner object to handle state machine callbacks, ensuring protocol-level types (like `IdBanner` or `SshMsgKexinit`) do not leak into the public API.

## Kaitai Struct Usage

Generated classes are in package `org.connectbot.sshlib.protocol`.

### Reading (parsing)

```kotlin
val stream = ByteBufferKaitaiStream(byteArray)
val message = SomeSshMessage(stream)
message._read()
val field = message.someField()
```

- `readU4be()` → `Long` (unsigned 32-bit big-endian)
- `readBytes(len: Long)` → `ByteArray`
- `readU1()` → `Int`

### Writing (serializing)

Allocate a writable stream with `ByteBufferKaitaiStream(capacityLong)`:

```kotlin
val stream = ByteBufferKaitaiStream(4L + payload.size)
stream.writeU4be(totalLength)   // 4-byte big-endian length
stream.writeU1(messageType)     // 1-byte message type
stream.writeBytes(payload)
stream.seek(0)
return stream.readBytesFull()
```

Key write methods on `KaitaiStream`:
- `writeU4be(Long)` — 4-byte big-endian unsigned int
- `writeU1(Int)` — 1-byte unsigned
- `writeBytes(ByteArray)` — raw bytes
- `writeS4be(Int)` — 4-byte big-endian signed int

### Serializing Kaitai structs

Use the `toByteArray()` extension from `KaitaiUtils.kt`:

```kotlin
val msg = SomeSshMessage()
msg.setField(createByteString(data))
msg._check()
val bytes = msg.toByteArray()
```

### Helper constructors

- `createByteString(ByteArray)` — wraps a byte array as a Kaitai ByteString field
- `createAsciiString(String)` — wraps an ASCII string
- `createUtf8String(String)` — wraps a UTF-8 string

### AsciiString size limit

Kaitai's `AsciiString` validates that the string is ≤ 65535 bytes. Do not use it for arbitrary-length binary blobs (e.g., public key blobs). Use `ByteString` instead.

## Coding Guidelines

- **API Surface**: Keep the public API surface minimal. Use `internal` visibility for all classes and interfaces that deal with protocol-level details (Kaitai structs, state machine callbacks, low-level crypto interfaces).
- **No Unchecked Exceptions**: No unchecked exceptions should be thrown in the library.

### Testability Patterns

- Pure logic extracted to top-level `internal fun` is directly unit-testable without annotation libraries.
- Follow the `selectPasswordMethods`, `keyBlobAlgorithmName`, `buildAgentMessage`, and `isConstraintSatisfied` patterns: extract from class body, pass state as parameters.
- Use `EqualsVerifier.forClass(Foo::class.java).verify()` to unit test `hashCode`/`equals` on any class that implements them.
- `data class` types with `ByteArray` fields need `EqualsVerifier.withPrefabValues(ByteArray::class.java, ...)`.
- Avoid `private` extension functions on `ByteArray?` inside `data class` — they cause `StackOverflowError` with EqualsVerifier. Use `contentEquals()` directly on non-null receivers.

## Concurrency Rules

This codebase has a carefully designed concurrency model. Violating these rules introduces
races, deadlocks, or thread starvation.

**`stateMachineDispatcher` is the single-threaded serialization point:**
- All reads and writes of protocol state (`pendingAuth`, `pendingChannelOpen`,
  `pendingChannelRequest`, `pendingGlobalRequest`, `currentAuthMethod`, `authResultChannel`,
  `infoRequestChannel`) must happen inside `withContext(stateMachineDispatcher)`.
- `PendingValue.complete()` and `completeExceptionally()` are non-`suspend` but must only be
  called from within the dispatcher. The teardown path in `startPacketLoop` wraps its cleanup
  in `withContext(stateMachineDispatcher)` for this reason.
- When you need to atomically set a `PendingValue` *and* send a packet or dispatch an event,
  use `PendingValue.setDirect()` inside a single `withContext(stateMachineDispatcher)` block.
  See `sendAuthRequest`, `openSessionChannel`, `sendChannelRequest`, and
  `sendTcpipForwardRequest` for the established pattern.

**Never use `runBlocking` inside coroutine code:**
- `processNextPacket` and all its callees are `suspend`. Call `suspend` functions directly.
- State machine callbacks that do I/O are declared `suspend` in `SshClientCallbacks`.
- `BlockingSshClient` is the only legitimate use of `runBlocking` — it is the intentional
  blocking adapter at the edge of the system.

**Channel and map thread safety:**
- All four channel maps (`channels`, `channelsByRemote`, `agentChannels`,
  `agentChannelsByRemote`) use `ConcurrentHashMap`. Use `ConcurrentHashMap` for any new
  shared mutable maps accessed from both the packet loop and the caller's coroutine.
- Use `Collections.synchronizedSet` (or `ConcurrentHashMap.newKeySet()`) for any shared
  mutable sets accessed from multiple coroutines.

**Window flow control:**
- Never busy-wait with `delay(N)` for window availability. Use the `Channel<Unit>(CONFLATED)`
  pattern: `windowAvailable.trySend(Unit)` in `onWindowAdjust`, `windowAvailable.receive()`
  in the send loop. Close the channel in the close path to unblock blocked senders.
- `remoteWindowSize` must be `@Volatile` because it is written by `onWindowAdjust` (packet
  loop coroutine) and read by send functions (caller's coroutine).

**`PendingValue<T>` contract:**
- `set(deferred)` — `suspend`, enters dispatcher, safe from any context.
- `setDirect(deferred)` — non-`suspend`, must be called from within `stateMachineDispatcher`.
- `complete(value)` — non-`suspend`, must be called from within `stateMachineDispatcher`;
  returns `Boolean` (true if a deferred was present).
- `completeExceptionally(e)` — non-`suspend`, must be called from within `stateMachineDispatcher`.
- `clearIfSame(expected)` — `suspend`, safe from any context; use in `finally` blocks to
  avoid clearing a deferred that has already been replaced by a subsequent request.
