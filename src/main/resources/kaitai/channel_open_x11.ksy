meta:
  id: channel_open_x11
  endian: be
  imports:
  - byte_string
doc: >
  The recipient should respond with a SSH_MSG_CHANNEL_OPEN_CONFIRMATION
  or SSH_MSG_CHANNEL_OPEN_FAILURE.
doc-ref: RFC 4254 section 6.3.2
seq:
- id: originator_address
  doc: IP address (e.g., "192.168.7.38")
  type: byte_string
- id: originator_port
  type: u4
