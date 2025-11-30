meta:
  id: mpint
  title: SSH mpint (big integer)
  endian: be
  xref:
    rfc: 4251
  license: CC0-1.0
doc: Big integers serialization format used by SSH.
doc-ref: 'https://tools.ietf.org/html/rfc4251#section-5'
seq:
  - id: len_body
    type: u4
  - id: body
    size: len_body
instances:
  length_in_bits:
    value: (len_body - 1) * 8
    doc: >
      Length of big integer in bits. In OpenSSH sources, this corresponds to
      `BN_num_bits` function.
