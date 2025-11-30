meta:
  id: ssh_enums
  title: SSH Enums
  license: CC0-1.0
enums:
  message_type:
    1: ssh_msg_disconnect
    2: ssh_msg_ignore
    3: ssh_msg_unimplemented
    4: ssh_msg_debug
    5: ssh_msg_service_request
    6: ssh_msg_service_accept
    7: ssh_msg_ext_info
    8: ssh_msg_newcompress
    20: ssh_msg_kexinit
    21: ssh_msg_newkeys
    30: ssh_msg_kex_method_specific_30
    31: ssh_msg_kex_method_specific_31
    32: ssh_msg_kex_method_specific_32
    33: ssh_msg_kex_method_specific_33
    34: ssh_msg_kex_method_specific_34
    35: ssh_msg_kex_method_specific_35
    36: ssh_msg_kex_method_specific_36
    37: ssh_msg_kex_method_specific_37
    38: ssh_msg_kex_method_specific_38
    39: ssh_msg_kex_method_specific_39
    40: ssh_msg_kex_method_specific_40
    41: ssh_msg_kex_method_specific_41
    42: ssh_msg_kex_method_specific_42
    43: ssh_msg_kex_method_specific_43
    44: ssh_msg_kex_method_specific_44
    45: ssh_msg_kex_method_specific_45
    46: ssh_msg_kex_method_specific_46
    47: ssh_msg_kex_method_specific_47
    48: ssh_msg_kex_method_specific_48
    49: ssh_msg_kex_method_specific_49
    50: ssh_msg_userauth_request
    51: ssh_msg_userauth_failure
    52: ssh_msg_userauth_success
    53: ssh_msg_userauth_banner
    60: ssh_msg_userauth_method_specific_60
    61: ssh_msg_userauth_method_specific_61
    62: ssh_msg_userauth_method_specific_62
    63: ssh_msg_userauth_method_specific_63
    64: ssh_msg_userauth_method_specific_64
    65: ssh_msg_userauth_method_specific_65
    66: ssh_msg_userauth_method_specific_66
    67: ssh_msg_userauth_method_specific_67
    68: ssh_msg_userauth_method_specific_68
    69: ssh_msg_userauth_method_specific_69
    70: ssh_msg_userauth_method_specific_70
    71: ssh_msg_userauth_method_specific_71
    72: ssh_msg_userauth_method_specific_72
    73: ssh_msg_userauth_method_specific_73
    74: ssh_msg_userauth_method_specific_74
    75: ssh_msg_userauth_method_specific_75
    76: ssh_msg_userauth_method_specific_76
    77: ssh_msg_userauth_method_specific_77
    78: ssh_msg_userauth_method_specific_78
    79: ssh_msg_userauth_method_specific_79
    80: ssh_msg_global_request
    81: ssh_msg_request_success
    82: ssh_msg_request_failure
    90: ssh_msg_channel_open
    91: ssh_msg_channel_open_confirmation
    92: ssh_msg_channel_open_failure
    93: ssh_msg_channel_window_adjust
    94: ssh_msg_channel_data
    95: ssh_msg_channel_extended_data
    96: ssh_msg_channel_eof
    97: ssh_msg_channel_close
    98: ssh_msg_channel_request
    99: ssh_msg_channel_success
    100: ssh_msg_channel_failure
  global_request_type:
    0: empty_response
    1: tcpip_forward
  kex_dh:
    30: ssh_msg_kexdh_init
    31: ssh_msg_kexdh_reply
  kex_dh_gex:
    30: ssh_msg_kex_dh_gex_request_old
    34: ssh_msg_kex_dh_gex_request
    31: ssh_msg_kex_dh_gex_group
    32: ssh_msg_kex_dh_gex_init
    33: ssh_msg_kex_dh_gex_reply
  kex_rsa:
    30: ssh_msg_kexrsa_pubkey
    31: ssh_msg_kexrsa_secret
    32: ssh_msg_kexrsa_done
  kex_ecdh:
    30: ssh_msg_kex_ecdh_init
    31: ssh_msg_kex_ecdh_reply
  kex_ecmqv:
    30: ssh_msg_kex_ecmqv_init
    31: ssh_msg_kex_ecmqv_reply
  kex_gssapi:
    30: ssh_msg_kexgss_init
    31: ssh_msg_kexgss_continue
    32: ssh_msg_kexgss_complete
    33: ssh_msg_kexgss_hostkey
    34: ssh_msg_kexgss_error
    40: ssh_msg_kexgss_groupreq
    41: ssh_msg_kexgss_group
  message_userauth_publickey:
    60: ssh_msg_userauth_pk_ok
  message_userauth_password:
    60: ssh_msg_userauth_passwd_changereq
  message_userauth_keyboard_interactive:
    60: ssh_msg_userauth_info_request
    61: ssh_msg_userauth_info_response
  message_userauth_gssapi_with_mic:
    60: ssh_msg_userauth_gssapi_response
    61: ssh_msg_userauth_gssapi_token
    63: ssh_msg_userauth_gssapi_exchange_complete
    64: ssh_msg_userauth_gssapi_error
    65: ssh_msg_userauth_gssapi_errtok
    66: ssh_msg_userauth_gssapi_mic
  disconnect_reason:
    1: ssh_disconnect_host_not_allowed_to_connect
    2: ssh_disconnect_protocol_error
    3: ssh_disconnect_key_exchange_failed
    4: ssh_disconnect_reserved
    5: ssh_disconnect_mac_error
    6: ssh_disconnect_compression_error
    7: ssh_disconnect_service_not_available
    8: ssh_disconnect_protocol_version_not_supported
    9: ssh_disconnect_host_key_not_verifiable
    10: ssh_disconnect_connection_lost
    11: ssh_disconnect_by_application
    12: ssh_disconnect_too_many_connections
    13: ssh_disconnect_auth_cancelled_by_user
    14: ssh_disconnect_no_more_auth_methods_available
    15: ssh_disconnect_illegal_user_name
  channel_connection_failure_reason:
    1: ssh_open_administratively_prohibited
    2: ssh_open_connect_failed
    3: ssh_open_unknown_channel_type
    4: ssh_open_resource_shortage
  publickey_subsystem_status:
    0: ssh_publickey_success
    1: ssh_publickey_access_denied
    2: ssh_publickey_storage_exceeded
    3: ssh_publickey_version_not_supported
    4: ssh_publickey_key_not_found
    5: ssh_publickey_key_not_supported
    6: ssh_publickey_key_already_present
    7: ssh_publickey_general_failure
    8: ssh_publickey_request_not_supported
    9: ssh_publickey_attribute_not_supported
