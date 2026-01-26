meta:
  id: userauth_request_keyboard_interactive
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4256 section 3.1
seq:
- id: language_tag
  type: byte_string
- id: submethods
  type: byte_string
