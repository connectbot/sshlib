meta:
  id: restrict_destination_constraint
  title: restrict-destination-v00@openssh.com Constraint
  endian: be
  imports:
  - byte_string
doc: |
  One hop entry for the restrict-destination-v00@openssh.com agent key constraint.
  from_hostname and from_keyspecs are empty for origin-side constraints.
seq:
  - id: from_hostname
    type: byte_string
    doc: Hostname of the previous hop (empty for origin)
  - id: num_from_keyspecs
    type: u4
    valid:
      expr: _ <= (_io.size - _io.pos) / 5
    doc: Number of from host key specs
  - id: from_keyspecs
    type: keyspec
    repeat: expr
    repeat-expr: num_from_keyspecs
    doc: Host key specs for the previous hop (empty for origin)
  - id: to_username
    type: byte_string
    doc: Destination username (empty = any user)
  - id: to_hostname
    type: byte_string
    doc: Destination hostname
  - id: num_to_hostspecs
    type: u4
    valid:
      expr: _ <= (_io.size - _io.pos) / 5
    doc: Number of destination host key specs
  - id: to_hostspecs
    type: keyspec
    repeat: expr
    repeat-expr: num_to_hostspecs
    doc: Destination host key specs
types:
  keyspec:
    seq:
      - id: keyblob
        type: byte_string
        doc: Host key blob
      - id: is_ca
        type: u1
        doc: 1 if this is a CA key, 0 if it is a direct host key
