meta:
  id: userauth_request_publickey_hostbound
  endian: be
  imports:
  - ascii_string
  - byte_string
doc-ref: OpenSSH publickey-hostbound-v00@openssh.com extension
doc: >
  Publickey authentication method fields for publickey-hostbound-v00@openssh.com.
  Identical to userauth_request_publickey but adds server_host_key before signature.
seq:
- id: has_signature
  type: u1
  doc: >
    FALSE (0) to query if the public key is acceptable for authentication.
    TRUE (1) to perform actual authentication with signature.
- id: public_key_algorithm_name
  type: ascii_string
  doc: Public key algorithm name
- id: public_key_blob
  type: byte_string
  doc: Public key blob (may contain certificates)
- id: server_host_key
  type: byte_string
  doc: Server's host key blob, binding the authentication to a specific destination
- id: signature
  type: byte_string
  doc: >
    Signature over session identifier and authentication request including server host key.
    Only present when has_signature is TRUE.
  if: has_signature != 0
