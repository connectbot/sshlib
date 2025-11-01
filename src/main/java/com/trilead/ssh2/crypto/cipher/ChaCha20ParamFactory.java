package com.trilead.ssh2.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Constructor;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Factory for creating ChaCha20 algorithm parameter specs.
 *
 * Tests whether the JCE provider supports ChaCha20ParameterSpec by attempting
 * to initialize a cipher with it. Falls back to IvParameterSpec if not supported.
 */
class ChaCha20ParamFactory
{
	private static final boolean USE_CHACHA20_PARAM_SPEC;
	private static final Constructor<?> CHACHA20_PARAM_SPEC_CONSTRUCTOR;

	static
	{
		Constructor<?> constructor = null;
		boolean useChaCha20ParamSpec = false;

		try
		{
			Class<?> chaCha20ParamSpecClass = Class.forName("javax.crypto.spec.ChaCha20ParameterSpec");
			constructor = chaCha20ParamSpecClass.getConstructor(byte[].class, int.class);

			byte[] testNonce = new byte[12];
			byte[] testKey = new byte[32];
			AlgorithmParameterSpec testParams = (AlgorithmParameterSpec) constructor.newInstance(testNonce, 0);
			SecretKeySpec testKeySpec = new SecretKeySpec(testKey, "ChaCha20");

			Cipher testCipher = Cipher.getInstance("ChaCha20");
			testCipher.init(Cipher.DECRYPT_MODE, testKeySpec, testParams);

			useChaCha20ParamSpec = true;
		}
		catch (Exception e)
		{
		}

		USE_CHACHA20_PARAM_SPEC = useChaCha20ParamSpec;
		CHACHA20_PARAM_SPEC_CONSTRUCTOR = constructor;
	}

	/**
	 * Creates an AlgorithmParameterSpec for ChaCha20 cipher initialization.
	 *
	 * @param nonce 12-byte nonce
	 * @param counter initial counter value
	 * @return ChaCha20ParameterSpec on desktop JDK, IvParameterSpec on Android
	 */
	static AlgorithmParameterSpec create(byte[] nonce, int counter)
	{
		if (USE_CHACHA20_PARAM_SPEC)
		{
			try
			{
				return (AlgorithmParameterSpec) CHACHA20_PARAM_SPEC_CONSTRUCTOR.newInstance(nonce.clone(), counter);
			}
			catch (Exception e)
			{
				throw new IllegalStateException("Failed to create ChaCha20ParameterSpec", e);
			}
		}
		else
		{
			return new IvParameterSpec(nonce.clone());
		}
	}

	/**
	 * Returns whether this platform uses ChaCha20ParameterSpec (true) or IvParameterSpec (false).
	 */
	static boolean usesChaCha20ParameterSpec()
	{
		return USE_CHACHA20_PARAM_SPEC;
	}
}
