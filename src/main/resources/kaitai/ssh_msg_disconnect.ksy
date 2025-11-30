meta:
  id: ssh_msg_disconnect
  endian: be
  imports:
  - ascii_string
  - ssh_enums
  - utf8_string
doc-ref: RFC 4253 section 11.1
doc: >
  This message causes an immediate termination of the connection. After
  this message, the sender must not send or receiver data. The receiver
  must not accept any data after receiving this message.
seq:
- id: reason_code
  doc: machine-readable reason for disconnection
  enum: ssh_enums::disconnect_reason
  type: u4
- id: description
  doc: human readable reason for disconnection in ISO-10646 UTF-8
  type: utf8_string
- id: language
  doc: language tag according to RFC 3066
  type: ascii_string
