meta:
  id: utf8_string
  title: SSH string (UTF-8)
  endian: be
  xref:
    rfc: 4251
  license: CC0-1.0
doc: >
  A integer-prefixed string in UTF-8 encoding. All strings presented to
  the user should be in UTF-8.
-webide-representation: '{value}'
doc-ref: 'https://tools.ietf.org/html/rfc4251#section-5'
seq:
  - id: len
    type: u4
    valid:
      expr: _ <= _io.size - _io.pos
  - id: value
    type: str
    size: len
    encoding: UTF-8
