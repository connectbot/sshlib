meta:
  id: userauth_publickey_signature_data
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4252 section 7
doc: >
  The data over which the signature is computed for publickey authentication.
  This is used to verify the signature sent by the client.
seq:
- id: session_identifier
  type: byte_string
  doc: Session identifier from key exchange
- id: message_type
  contents:
  - 50
  doc: SSH_MSG_USERAUTH_REQUEST (50)
- id: user_name
  type: byte_string
  doc: User name
- id: service_name
  type: byte_string
  doc: Service name
- id: method_name
  type: byte_string
  doc: Authentication method name (should be "publickey")
- id: has_signature
  contents:
  - 1
  doc: TRUE (1)
- id: public_key_algorithm_name
  type: byte_string
  doc: Public key algorithm name
- id: public_key_blob
  type: byte_string
  doc: Public key to be used for authentication
