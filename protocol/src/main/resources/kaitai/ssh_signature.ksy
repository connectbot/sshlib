meta:
  id: ssh_signature
  endian: be
  imports:
  - byte_string
  - ecdsa_signature_blob
  - ssh_dss_signature_blob
  - ssh_ed25519_signature_blob
  - ssh_ed448_signature_blob
  - ssh_rsa_signature_blob
  - sk_ed25519_signature_blob
  - sk_ecdsa_p256_signature_blob
doc-ref: RFC 4253 section 6.6
doc: >
  Generic SSH signature structure. The signature blob format is defined
  by the public key algorithm.
seq:
- id: algorithm_name_len
  type: u4
- id: algorithm_name
  type: str
  size: algorithm_name_len
  encoding: ASCII
- id: signature_blob
  type:
    switch-on: algorithm_name
    cases:
      '"ssh-rsa"': ssh_rsa_signature_blob
      '"rsa-sha2-256"': ssh_rsa_signature_blob
      '"rsa-sha2-512"': ssh_rsa_signature_blob
      '"ssh-dss"': ssh_dss_signature_blob
      '"ecdsa-sha2-nistp256"': ecdsa_signature_blob
      '"ecdsa-sha2-nistp384"': ecdsa_signature_blob
      '"ecdsa-sha2-nistp521"': ecdsa_signature_blob
      '"ssh-ed25519"': ssh_ed25519_signature_blob
      '"ssh-ed448"': ssh_ed448_signature_blob
      '"sk-ssh-ed25519@openssh.com"': sk_ed25519_signature_blob
      '"sk-ecdsa-sha2-nistp256@openssh.com"': sk_ecdsa_p256_signature_blob
      _: byte_string
