/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2015 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.trilead.ssh2.crypto.key;

import java.security.Key;

/**
 * Java representation of a native Ed25519 key.
 *
 * @author Kenny Root
 */
public class Ed25519Key implements Key {
	private final byte[] keyBytes;

	protected Ed25519Key(byte[] keyBytes) {
		this.keyBytes = keyBytes;
	}

	public String getAlgorithm() {
		return "Ed25519";
	}

	public String getFormat() {
		return "RAW";
	}

	public byte[] getEncoded() {
		return keyBytes;
	}
}
