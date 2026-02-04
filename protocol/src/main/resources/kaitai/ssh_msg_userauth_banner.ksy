meta:
  id: ssh_msg_userauth_banner
  endian: be
  imports:
  - byte_string
  - utf8_string
doc-ref: RFC 4252 section 5.4
seq:
- id: message
  type: utf8_string
  doc: banner message in UTF-8 encoding
- id: language_tag
  type: byte_string
  doc: language tag in RFC 3066 format
