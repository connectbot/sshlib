meta:
  id: ssh_msg_userauth_passwd_changereq
  endian: be
  imports:
  - ascii_string
  - utf8_string
doc-ref: RFC 4252 section 8
doc: >
  Server requests that the client change the password. The client
  may respond with a new password change request or try a different
  authentication method.
seq:
- id: prompt
  type: utf8_string
  doc: Prompt message in UTF-8 encoding
- id: language_tag
  type: ascii_string
  doc: Language tag in RFC 3066 format
