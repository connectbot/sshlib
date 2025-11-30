meta:
  id: gssapi_keyex_hash
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4462 section 4
seq:
- id: session_identifier
  type: byte_string
- id: request_identifier
  contents:
  - 50
- id: user_name
  type: byte_string
- id: service_name
  type: byte_string
- id: request_type
  contents: gssapi-keyex
