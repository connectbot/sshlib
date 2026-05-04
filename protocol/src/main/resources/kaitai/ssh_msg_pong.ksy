meta:
  id: ssh_msg_pong
  endian: be
  imports:
  - byte_string
doc-ref: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL
doc: >
  A pong reply to SSH_MSG_PING. The data field must be an exact copy of
  the data from the corresponding ping message.
seq:
- id: data
  type: byte_string
