meta:
  id: ssh_msg_kex_ecmqv_reply
  endian: be
  imports:
  - byte_string
doc-ref: RFC 5656 section 5
doc: Elliptic Curve Menezes-Qu-Vanstone key exchange reply packet
seq:
- id: k_s
  doc: Server's public host key
  type: byte_string
- id: q_s
  doc: Server's ephemeral public key octet string
  type: byte_string
- id: hmac_tag
  doc: HMAC tag computed on H using the shared secret
  type: byte_string
