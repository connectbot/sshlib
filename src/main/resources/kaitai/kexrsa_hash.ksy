meta:
  id: kexrsa_hash
  endian: be
  imports:
  - byte_string
  - mpint
doc: >
  This value is called the exchange hash, and it is used to
  authenticate the key exchange. The exchange hash SHOULD be
  kept secret.
doc-ref: RSA 4432 section 4
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
- id: k_t
  doc: the transient RSA key
  type: byte_string
- id: encrypted_secret
  doc: RSAES_OAEP_ENCRYPT(K_T, K), the encrypted secret
  type: byte_string
- id: k
  doc: the shared secret
  type: mpint
