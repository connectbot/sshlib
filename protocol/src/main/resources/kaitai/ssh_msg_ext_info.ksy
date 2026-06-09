meta:
  id: ssh_msg_ext_info
  endian: be
  imports:
  - ascii_string
  - byte_string
doc-ref: RFC 8308 section 2.3
doc: >
  Extension negotiation message. Sent after SSH_MSG_NEWKEYS to advertise
  supported extensions and their values. Each extension is a name-value pair.
seq:
- id: num_extensions
  type: u4
  valid:
    expr: _ <= (_io.size - _io.pos) / 8
  doc: Number of extension name-value pairs
- id: extensions
  type: extension
  repeat: expr
  repeat-expr: num_extensions
types:
  extension:
    seq:
    - id: extension_name
      type: ascii_string
      doc: Extension name
    - id: extension_value
      type: byte_string
      doc: Extension value (binary data, interpretation depends on extension)
