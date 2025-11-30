meta:
  id: ssh_msg_kexinit
  endian: be
  imports:
  - name_list
doc-ref: RFC 4253 section 7.1
seq:
- id: cookie
  size: 16
- id: kex_algorithms
  type: name_list
- id: server_host_key_algorithms
  type: name_list
- id: encryption_algorithms_client_to_server
  type: name_list
- id: encryption_algorithms_server_to_client
  type: name_list
- id: mac_algorithms_client_to_server
  type: name_list
- id: mac_algorithms_server_to_client
  type: name_list
- id: compression_algorithms_client_to_server
  type: name_list
- id: compression_algorithms_server_to_client
  type: name_list
- id: languages_client_to_server
  type: name_list
- id: languages_server_to_client
  type: name_list
- id: first_kex_packet_follows
  type: u1
- id: reserved
  type: u4
