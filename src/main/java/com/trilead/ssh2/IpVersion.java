
package com.trilead.ssh2;

/**
 * Allow the caller to restrict the IP version of the connection to
 * be established.
 */
public enum IpVersion {
	IPV4_AND_IPV6,
	IPV4_ONLY,
	IPV6_ONLY
}
