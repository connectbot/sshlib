package com.trilead.ssh2.crypto.cipher;

import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.Constructor;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Factory for creating ChaCha20 algorithm parameter specs with compatibility
 * across different Java platforms.
 *
 * Desktop JDK requires ChaCha20ParameterSpec (with explicit counter support).
 * Android prior to API 35 doesn't have ChaCha20ParameterSpec and uses IvParameterSpec.
 *
 * This factory detects the available class at runtime and creates the appropriate
 * parameter spec without causing ClassNotFoundException on platforms that don't
 * support ChaCha20ParameterSpec.
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
			useChaCha20ParamSpec = true;
		}
		catch (ClassNotFoundException | NoSuchMethodException e)
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
