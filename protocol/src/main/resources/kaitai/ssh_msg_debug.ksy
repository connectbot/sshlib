meta:
  id: ssh_msg_debug
  endian: be
  imports:
  - ascii_string
  - utf8_string
doc-ref: RFC 4253 section 11.3
doc: >
  This is a debug message that may help with debugging the connection. If
  "always_display" is true, then this message should always be displayed.
  Otherwise it should only be displayed if the user specifically requested
  debugging output.
seq:
- id: always_display
  type: u1
- id: message
  doc: debug message in ISO-10646 UTF-8 encoding
  type: utf8_string
- id: language
  doc: language tag according to RFC 3066
  type: ascii_string
