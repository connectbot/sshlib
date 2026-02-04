meta:
  id: channel_open_tun_openssh
  endian: be
  imports: []
doc-ref: openssh-PROTOCOL.txt
seq:
- id: tun_mode
  type: u4
  doc: Tunnel mode (SSH_TUNMODE_POINTOPOINT or SSH_TUNMODE_ETHERNET)
- id: tun_unit
  type: u4
  doc: Tunnel device unit number (or 0x7fffffff for auto-allocation)
