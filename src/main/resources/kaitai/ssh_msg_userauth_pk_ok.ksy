meta:
  id: ssh_msg_userauth_pk_ok
  endian: be
  imports:
  - ascii_string
  - byte_string
doc-ref: RFC 4252 section 7
doc: >
  Response to publickey authentication query indicating that the
  public key is acceptable for authentication.
seq:
- id: public_key_algorithm_name
  type: ascii_string
  doc: Public key algorithm name from the request
- id: public_key_blob
  type: byte_string
  doc: Public key blob from the request
