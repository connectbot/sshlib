meta:
  id: ssh_msg_userauth_info_response
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4256 section 3.4
seq:
- id: num_responses
  type: u4
- id: responses
  type: byte_string
  repeat: expr
  repeat-expr: num_responses
