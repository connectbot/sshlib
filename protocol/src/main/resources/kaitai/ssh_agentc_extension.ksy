meta:
  id: ssh_agentc_extension
  title: SSH_AGENTC_EXTENSION
  endian: be
  imports:
  - byte_string
doc: |
  Extension request message (type 27).
  Used for protocol extensions like session-bind@openssh.com.
seq:
  - id: extension_name
    type: byte_string
    doc: Extension name (e.g., "session-bind@openssh.com")
  - id: extension_data
    size-eos: true
    doc: Extension-specific payload
