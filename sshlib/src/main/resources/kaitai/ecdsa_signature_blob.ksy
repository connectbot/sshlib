meta:
  id: ecdsa_signature_blob
  endian: be
  imports:
  - mpint
doc-ref: RFC 5656 section 3.1.2
seq:
- id: len_blob
  type: u4
- id: blob
  type: ecdsa_signature_inner
  size: len_blob
types:
  ecdsa_signature_inner:
    seq:
    - id: r
      type: mpint
      doc: ECDSA signature component r
    - id: s
      type: mpint
      doc: ECDSA signature component s
