meta:
  id: kex_ecmqv_hash
  endian: be
  imports:
  - byte_string
  - mpint
doc-ref: RFC 5656 section 5
doc: >
  The hash H is formed by applying the hash algorithm specified
  by the chosen key exchange method to the concatenation of the
  following values.
seq:
- id: v_c
  doc: the client's identification string (CR and LF excluded)
  type: byte_string
- id: v_s
  doc: the server's identification string (CR and LF excluded)
  type: byte_string
- id: i_c
  doc: the payload of the client's SSH_MSG_KEXINIT
  type: byte_string
- id: i_s
  doc: the payload of the server's SSH_MSG_KEXINIT
  type: byte_string
- id: k_s
  doc: the server's public host key
  type: byte_string
- id: q_c
  doc: client's ephemeral public key octet string
  type: byte_string
- id: q_s
  doc: server's ephemeral public key octet string
  type: byte_string
- id: k
  doc: the shared secret
  type: mpint
