meta:
  id: userauth_publickey_signature_data_any
  endian: be
  imports:
    - byte_string
    - ascii_string
    - utf8_string
doc: >
  The data over which the signature is computed for publickey authentication.
  This handles both the standard RFC 4252 version and the OpenSSH
  publickey-hostbound-v00@openssh.com extension.
seq:
  - id: session_identifier
    type: byte_string
    doc: Session identifier from key exchange
  - id: message_type
    contents: [50]
    doc: SSH_MSG_USERAUTH_REQUEST (50)
  - id: user_name
    type: utf8_string
    doc: User name
  - id: service_name
    type: ascii_string
    doc: Service name
    valid:
      expr: _.value == "ssh-connection"
  - id: method_name
    type: ascii_string
    doc: Authentication method name
    valid:
      expr: _.value == "publickey" or _.value == "publickey-hostbound-v00@openssh.com"
  - id: has_signature
    contents: [1]
    doc: TRUE (1)
  - id: public_key_algorithm_name
    type: ascii_string
    doc: Public key algorithm name
  - id: public_key_blob
    type: byte_string
    doc: Public key to be used for authentication
  - id: server_host_key
    type: byte_string
    doc: Server's host key, binding the signature to the intended destination (only for hostbound method)
    if: method_name.value == "publickey-hostbound-v00@openssh.com"
