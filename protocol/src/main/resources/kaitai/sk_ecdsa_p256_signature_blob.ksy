meta:
  id: sk_ecdsa_p256_signature_blob
  endian: be
  imports:
    - byte_string
    - ecdsa_signature_blob
doc: >
  OpenSSH Security Key ECDSA P-256 signature blob.
  Defined in OpenSSH PROTOCOL.u2f section 3.2.
seq:
  - id: signature
    type: ecdsa_signature_blob
    doc: ECDSA signature material (mpint r || mpint s)
  - id: flags
    type: u1
    doc: FIDO2 device flags (e.g. 0x01 for UP)
  - id: counter
    type: u4
    doc: FIDO2 device signature counter
