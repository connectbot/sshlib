meta:
  id: ssh_msg_kexdh_reply
  endian: be
  imports:
  - byte_string
  - mpint
doc-ref: RFC 4253 section 8
doc: Diffie-Hellman key exchange reply packet
seq:
- id: server_key
  doc: Server's key (K_S) in the appropriate format.
  type: byte_string
- id: f
  doc: >
    Server's public key portion of ephemeral Diffie-Hellman key exchange
    (i.e., f = g^y mod p).
  type: mpint
- id: signature_h
  doc: >
    Signature over hash of the connection details. For the server,
    K = e^y mod p. See "kexdh_hash" type for contents of the hash.
  type: byte_string
