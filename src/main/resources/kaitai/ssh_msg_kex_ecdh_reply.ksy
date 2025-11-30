meta:
  id: ssh_msg_kex_ecdh_reply
  endian: be
  imports:
  - byte_string
doc-ref: RFC 5656 section 4
doc: Elliptic Curve Diffie-Hellman key exchange reply packet
seq:
- id: k_s
  doc: Server's public host key
  type: byte_string
- id: q_s
  doc: Server's ephemeral public key octet string
  type: byte_string
- id: signature_h
  doc: Signature on the exchange hash
  type: byte_string
