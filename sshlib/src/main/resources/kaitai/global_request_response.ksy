meta:
  id: global_request_response
  endian: be
  imports:
  - global_request_response_empty
  - global_request_response_tcpip_forward
  - ssh_enums
doc-ref: RFC 4254 section 4
params:
- id: request_type
  type: u1
  enum: ssh_enums::global_request_type
seq:
- id: global_request_response_fields
  type:
    switch-on: request_type
    cases:
      ssh_enums::global_request_type::tcpip_forward: global_request_response_tcpip_forward
      _: global_request_response_empty
