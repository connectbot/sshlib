meta:
  id: channel_request_env
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 6.4
seq:
- id: variable_name
  type: byte_string
- id: variable_value
  type: byte_string
