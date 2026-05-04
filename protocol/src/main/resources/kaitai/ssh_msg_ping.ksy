meta:
  id: ssh_msg_ping
  endian: be
  imports:
  - byte_string
doc-ref: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL
doc: >
  A ping message sent by either the client or server. The recipient must
  reply with SSH_MSG_PONG containing the same data.
seq:
- id: data
  type: byte_string
