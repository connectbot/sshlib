# SSH lifecycle TLA+ model

This model uses TLA+ to explore the SSH client's connection and channel state machines and check
that their safety rules hold for every reachable state. It is intended to catch invalid behavior
such as bypassing authentication, treating an unparsed packet as genuine, sending higher-layer
packets during key exchange, or applying channel effects to the wrong channel. It does not
currently check liveness properties.

The connection model covers initial key exchange, authentication, rekeying, and disconnection.
The channel model adds a small registry of channels so TLC can verify that an operation on one
channel does not affect another. Global connection operations must leave channels unchanged except
for disconnection, which closes every allocated channel. Rekeying must also preserve channel state
and allow valid channel operations to resume with the same guards afterward.

Most of the model is generated from the KStateMachine declarations and their typed TLA+ metadata:

- `SshClientStateMachineGenerated.tla` contains the generated states, transitions, guards, and
  side effects. Do not edit it directly.
- `SshClientStateMachine.tla` defines the handwritten safety properties.
- `SshClientStateMachine.cfg` configures the states and properties that TLC explores.

Regenerate the structural model with:

```bash
./gradlew :sshlib:generateSshStateMachineTla
```

The unit tests fail if the checked-in generated model is out of date. To run TLC with an official
`tla2tools.jar`, use:

```bash
./gradlew :sshlib:checkSshStateMachineTla \
  -Ptla2toolsJar=/path/to/tla2tools.jar
```

`TLA2TOOLS_JAR=/path/to/tla2tools.jar` may be used instead of the Gradle property. CI downloads the
pinned official release, verifies its SHA-256 digest, and runs the same check.
