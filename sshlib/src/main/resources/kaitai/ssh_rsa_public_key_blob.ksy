meta:
  id: ssh_rsa_public_key_blob
  endian: be
  imports:
  - mpint
doc-ref: RFC 4253 section 6.6
seq:
- id: e
  type: mpint
  doc: RSA public exponent
- id: n
  type: mpint
  doc: RSA modulus
