meta:
  id: ssh_msg_kexrsa_secret
  endian: be
  imports:
  - mpint
doc-ref: RFC 4432 section 4
seq:
- id: encrypted_k
  type: mpint
  doc: RSAES-OAEP-ENCRYPT(K_T, K); where K is the shared secret
