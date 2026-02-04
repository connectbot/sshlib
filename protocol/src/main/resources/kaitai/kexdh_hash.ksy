meta:
  id: kexdh_hash
  endian: be
  imports:
  - byte_string
  - mpint
doc-ref: RFC 4253 section 8
seq:
- id: v_c
  doc: the client's identification string
  type: byte_string
- id: v_s
  doc: the server's identification string
  type: byte_string
- id: i_c
  doc: the payload of the client's SSH_MSG_KEXINIT
  type: byte_string
- id: i_s
  doc: the payload of the server's SSH_MSG_KEXINIT
  type: byte_string
- id: k_s
  doc: the host key
  type: byte_string
- id: e
  doc: exchange value sent by the client
  type: mpint
- id: f
  doc: exchange value sent by the server
  type: mpint
- id: k
  doc: the shared secret
  type: mpint
