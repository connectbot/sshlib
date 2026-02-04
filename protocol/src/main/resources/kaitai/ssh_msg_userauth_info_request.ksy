meta:
  id: ssh_msg_userauth_info_request
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4256 section 3.2
seq:
- id: name
  type: byte_string
- id: instruction
  type: byte_string
- id: language_tag
  type: byte_string
- id: num_prompts
  type: u4
- id: prompts
  type: prompt
  repeat: expr
  repeat-expr: num_prompts
types:
  prompt:
    seq:
    - id: prompt
      type: byte_string
    - id: echo
      type: u1
