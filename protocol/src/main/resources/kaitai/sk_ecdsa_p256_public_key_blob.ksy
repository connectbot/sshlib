meta:
  id: sk_ecdsa_p256_public_key_blob
  endian: be
  imports:
    - byte_string
doc: >
  OpenSSH Security Key ECDSA P-256 public key blob.
  Defined in OpenSSH PROTOCOL.u2f section 3.1.
seq:
  - id: curve_name_len
    type: u4
    valid: 8
  - id: curve_name
    contents: "nistp256"
  - id: public_key
    type: byte_string
    doc: Uncompressed SEC1 point (0x04 || X || Y)
  - id: application
    type: byte_string
    doc: Relying-party identifier (e.g. "ssh:")
