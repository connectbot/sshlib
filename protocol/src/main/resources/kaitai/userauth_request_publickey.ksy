meta:
  id: userauth_request_publickey
  endian: be
  imports:
  - ascii_string
  - byte_string
doc-ref: RFC 4252 section 7
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
- id: signature
  type: byte_string
  doc: >
    Signature over session identifier and authentication request.
    Only present when has_signature is TRUE.
  if: has_signature != 0
