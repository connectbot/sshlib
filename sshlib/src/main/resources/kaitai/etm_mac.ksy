meta:
  id: etm_mac
  endian: be
  imports: []
seq:
- id: sequence_number
  type: u4
- id: len_encrypted_packet
  type: u4
- id: encrypted_packet
  size: len_encrypted_packet
