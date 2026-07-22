# SSH lifecycle TLA+ model

`SshClientStateMachineGenerated.tla` is generated from the real KStateMachine declaration.
Do not edit it directly. `SshClientStateMachine.tla` contains the handwritten invariants, and
`SshClientStateMachine.cfg` tells TLC which invariants to check.

Regenerate the structural model with:

```bash
./gradlew :sshlib:generateSshStateMachineTla
```

The unit test suite fails when the generated model does not match the checked-in file. To run TLC
after obtaining an official `tla2tools.jar`, use:

```bash
./gradlew :sshlib:checkSshStateMachineTla \
  -Ptla2toolsJar=/path/to/tla2tools.jar
```

`TLA2TOOLS_JAR=/path/to/tla2tools.jar` can be used instead of the Gradle property.

The generated model intentionally abstracts packet bodies and cryptographic data. Its boundary is
the lifecycle state, transition event, event provenance, rekey status, and declared side effects.

## State counts

The generated model currently has 11 leaf lifecycle states and 33 named transitions. TLC's
"distinct states" statistic is intentionally larger: it counts complete valuations of lifecycle
state, previous state, rekey history, last event, provenance, and effects. That statistic is not
directly comparable to the node count of a learned Mealy machine such as an inferred OpenSSH model.
