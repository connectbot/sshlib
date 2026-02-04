meta:
  id: ascii_string
  title: SSH string (ASCII)
  endian: be
  xref:
    rfc: 4251
  license: CC0-1.0
doc: >
  A integer-prefixed string in ASCII encoding. All internal strings
  are represented in ASCII.
doc-ref: 'https://tools.ietf.org/html/rfc4251#section-5'
-webide-representation: '{value}'
seq:
  - id: len
    type: u4
    valid:
      expr: _ <= 65535
  - id: value
    type: str
    size: len
    encoding: ASCII
