meta:
  id: byte_string
  title: SSH string (bytes)
  endian: be
  xref:
    rfc: 4251
  license: CC0-1.0
doc: >
  An integer-prefixed byte array designed to be used for arbitrary data
  that is not expected to be a string.
-webide-representation: '{value}'
seq:
  - id: len_data
    type: u4
    valid:
      expr: _ <= _io.size - _io.pos
  - id: data
    size: len_data
