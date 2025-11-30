meta:
  id: userauth_request_password
  endian: be
  imports:
  - utf8_string
doc-ref: RFC 4252 section 8
seq:
- id: change_password
  type: u1
- id: plaintext_password
  type: utf8_string
  doc: plaintext password in UTF-8
- id: new_plaintext_password
  type: utf8_string
  doc: new password in UTF-8
  if: change_password != 0
