meta:
  id: userauth_request_hostbased
  endian: be
  imports:
  - ascii_string
  - byte_string
  - utf8_string
doc-ref: RFC 4252 section 9
seq:
- id: algorithm
  type: ascii_string
  doc: public key algorithm for host key
- id: host_key
  type: byte_string
  doc: public host key and certificates for client host
- id: client_host_name
  type: byte_string
  doc: client host name expressed as the FQDN in US-ASCII
- id: user_name
  type: utf8_string
  doc: user name on the client host in UTF-8
