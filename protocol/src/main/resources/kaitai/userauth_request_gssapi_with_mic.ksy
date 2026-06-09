meta:
  id: userauth_request_gssapi_with_mic
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4462 section 3.2
seq:
- id: num_mechanisms
  type: u4
  valid:
    expr: _ <= (_io.size - _io.pos) / 4
  doc: The number of mechanism OIDs client supports
- id: mechanisms
  type: byte_string
  repeat: expr
  repeat-expr: num_mechanisms
  doc: Mechanism OIDs encoded as ASN.1 DER rules
