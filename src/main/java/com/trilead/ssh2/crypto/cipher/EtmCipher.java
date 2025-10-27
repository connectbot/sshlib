package com.trilead.ssh2.crypto.cipher;

/**
 * Marker interface for Encrypt-then-MAC (EtM) cipher modes.
 * <p>
 * EtM ciphers authenticate the ciphertext rather than plaintext, providing
 * better security properties. Used by SSH cipher modes like chacha20-poly1305.
 */
public interface EtmCipher {
}
