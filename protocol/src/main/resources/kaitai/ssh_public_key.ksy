meta:
  id: ssh_public_key
  endian: be
  imports:
  - byte_string
  - ecdsa_public_key_blob
  - ssh_dss_public_key_blob
  - ssh_ed25519_public_key_blob
  - ssh_ed448_public_key_blob
  - ssh_rsa_public_key_blob
doc-ref: RFC 4253 section 6.6
doc: >
  Generic SSH public key structure. The key blob format is defined
  by the public key algorithm.
seq:
- id: algorithm_name_len
  type: u4
- id: algorithm_name
  type: str
  size: algorithm_name_len
  encoding: ASCII
- id: key_blob
  type:
    switch-on: algorithm_name
    cases:
      '"ssh-rsa"': ssh_rsa_public_key_blob
      '"ssh-dss"': ssh_dss_public_key_blob
      '"ecdsa-sha2-nistp256"': ecdsa_public_key_blob
      '"ecdsa-sha2-nistp384"': ecdsa_public_key_blob
      '"ecdsa-sha2-nistp521"': ecdsa_public_key_blob
      '"ssh-ed25519"': ssh_ed25519_public_key_blob
      '"ssh-ed448"': ssh_ed448_public_key_blob
      _: byte_string
