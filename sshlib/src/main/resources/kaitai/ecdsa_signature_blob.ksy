meta:
  id: ecdsa_signature_blob
  endian: be
  imports:
  - mpint
doc-ref: RFC 5656 section 3.1.2
seq:
- id: r
  type: mpint
  doc: ECDSA signature component r
- id: s
  type: mpint
  doc: ECDSA signature component s
