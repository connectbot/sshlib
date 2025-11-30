meta:
  id: userauth_request_gssapi_keyex
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4462 section 4
seq:
- id: mic
  type: byte_string
  doc: Obtained by calling GSS_GetMIC over gssapi_keyex_hash
