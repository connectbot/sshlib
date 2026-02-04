meta:
  id: ecdsa_public_key_blob
  endian: be
  imports:
  - ascii_string
  - byte_string
doc-ref: RFC 5656 section 3.1
seq:
- id: curve_identifier
  type: ascii_string
  doc: Elliptic curve identifier (e.g., "nistp256")
- id: q
  type: byte_string
  doc: Public key point Q (SEC1 octet string encoding)
