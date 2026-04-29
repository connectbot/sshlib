meta:
  id: userauth_publickey_hostbound_signature_data
  endian: be
  imports:
  - byte_string
doc-ref: OpenSSH publickey-hostbound-v00@openssh.com extension
doc: >
  The data over which the signature is computed for publickey-hostbound authentication.
  Identical to userauth_publickey_signature_data but method_name is
  "publickey-hostbound-v00@openssh.com" and server_host_key is appended.
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
  doc: Authentication method name ("publickey-hostbound-v00@openssh.com")
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
- id: server_host_key
  type: byte_string
  doc: Server's host key, binding the signature to the intended destination
