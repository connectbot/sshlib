package com.trilead.ssh2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Tests for DHGexParameters validation and construction logic.
 * These tests ensure proper parameter validation for Diffie-Hellman Group Exchange.
 */
public class DHGexParametersTest {

	@Test
	public void testDefaultConstructor() {
		DHGexParameters params = new DHGexParameters();

		// Default values should be 1024, 1024, 4096
		assertEquals("Default min group length should be 1024", 1024, params.getMin_group_len());
		assertEquals("Default preferred group length should be 1024", 1024, params.getPref_group_len());
		assertEquals("Default max group length should be 4096", 4096, params.getMax_group_len());
	}

	@Test
	public void testSingleParameterConstructorWithValidValue() {
		DHGexParameters params = new DHGexParameters(2048);

		// Single parameter constructor sets min and max to 0
		assertEquals("Min should be 0 for old-style request", 0, params.getMin_group_len());
		assertEquals("Preferred should be set value", 2048, params.getPref_group_len());
		assertEquals("Max should be 0 for old-style request", 0, params.getMax_group_len());
	}

	@Test
	public void testSingleParameterConstructorMinBoundary() {
		// Test minimum allowed value (1024)
		DHGexParameters params = new DHGexParameters(1024);
		assertEquals("Min allowed value should be accepted", 1024, params.getPref_group_len());
	}

	@Test
	public void testSingleParameterConstructorMaxBoundary() {
		// Test maximum allowed value (8192)
		DHGexParameters params = new DHGexParameters(8192);
		assertEquals("Max allowed value should be accepted", 8192, params.getPref_group_len());
	}

	@Test
	public void testSingleParameterConstructorBelowMinimum() {
		try {
			new DHGexParameters(1023);
			fail("Should throw IllegalArgumentException for value below minimum");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate out of range",
					"pref_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testSingleParameterConstructorAboveMaximum() {
		try {
			new DHGexParameters(8193);
			fail("Should throw IllegalArgumentException for value above maximum");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate out of range",
					"pref_group_len out of range!", e.getMessage());
	}
	}

	@Test
	public void testSingleParameterConstructorZero() {
		try {
			new DHGexParameters(0);
			fail("Should throw IllegalArgumentException for zero");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate out of range",
					"pref_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testSingleParameterConstructorNegative() {
		try {
			new DHGexParameters(-1);
			fail("Should throw IllegalArgumentException for negative value");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate out of range",
					"pref_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorValidValues() {
		DHGexParameters params = new DHGexParameters(1024, 2048, 4096);

		assertEquals("Min should be set correctly", 1024, params.getMin_group_len());
		assertEquals("Preferred should be set correctly", 2048, params.getPref_group_len());
		assertEquals("Max should be set correctly", 4096, params.getMax_group_len());
	}

	@Test
	public void testThreeParameterConstructorAllSame() {
		// All three values can be the same
		DHGexParameters params = new DHGexParameters(2048, 2048, 2048);

		assertEquals("Min should be 2048", 2048, params.getMin_group_len());
		assertEquals("Preferred should be 2048", 2048, params.getPref_group_len());
		assertEquals("Max should be 2048", 2048, params.getMax_group_len());
	}

	@Test
	public void testThreeParameterConstructorMinBelowRange() {
		try {
			new DHGexParameters(1023, 2048, 4096);
			fail("Should throw IllegalArgumentException for min below range");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate min out of range",
					"min_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorMinAboveRange() {
		try {
			new DHGexParameters(8193, 8193, 8193);
			fail("Should throw IllegalArgumentException for min above range");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate min out of range",
					"min_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorPrefBelowRange() {
		try {
			new DHGexParameters(1024, 1023, 4096);
			fail("Should throw IllegalArgumentException for pref below range");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate pref out of range",
					"pref_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorPrefAboveRange() {
		try {
			new DHGexParameters(1024, 8193, 8193);
			fail("Should throw IllegalArgumentException for pref above range");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate pref out of range",
					"pref_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorMaxBelowRange() {
		try {
			new DHGexParameters(1024, 1024, 1023);
			fail("Should throw IllegalArgumentException for max below range");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate max out of range",
					"max_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorMaxAboveRange() {
		try {
			new DHGexParameters(1024, 2048, 8193);
			fail("Should throw IllegalArgumentException for max above range");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate max out of range",
					"max_group_len out of range!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorPrefBelowMin() {
		try {
			new DHGexParameters(2048, 1024, 4096);
			fail("Should throw IllegalArgumentException when pref < min");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate pref incompatible with min/max",
					"pref_group_len is incompatible with min and max!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorPrefAboveMax() {
		try {
			new DHGexParameters(1024, 4096, 2048);
			fail("Should throw IllegalArgumentException when pref > max");
		} catch (IllegalArgumentException e) {
			assertEquals("Error message should indicate pref incompatible with min/max",
					"pref_group_len is incompatible with min and max!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorMaxBelowMin() {
		try {
			// When max < min and pref is between them, pref validation happens first
			new DHGexParameters(4096, 4096, 2048);
			fail("Should throw IllegalArgumentException when max < min");
		} catch (IllegalArgumentException e) {
			// Pref validation happens before max<min check in the actual code
			assertEquals("Error message should indicate pref incompatibility",
					"pref_group_len is incompatible with min and max!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorMaxSmallerThanMin() {
		try {
			// Test case where pref is valid relative to individual bounds
			// but max < min should still be caught
			new DHGexParameters(4096, 3072, 2048);
			fail("Should throw IllegalArgumentException when max < min");
		} catch (IllegalArgumentException e) {
			// With pref between max and min, pref check triggers first
			assertEquals("Error message depends on validation order",
					"pref_group_len is incompatible with min and max!", e.getMessage());
		}
	}

	@Test
	public void testThreeParameterConstructorPrefEqualsMin() {
		// Pref can equal min
		DHGexParameters params = new DHGexParameters(2048, 2048, 4096);

		assertEquals("Pref equals min should be valid", 2048, params.getPref_group_len());
		assertEquals("Min should be correct", 2048, params.getMin_group_len());
	}

	@Test
	public void testThreeParameterConstructorPrefEqualsMax() {
		// Pref can equal max
		DHGexParameters params = new DHGexParameters(1024, 4096, 4096);

		assertEquals("Pref equals max should be valid", 4096, params.getPref_group_len());
		assertEquals("Max should be correct", 4096, params.getMax_group_len());
	}

	@Test
	public void testThreeParameterConstructorMinEqualsMax() {
		// Min can equal max (and pref must also equal them)
		DHGexParameters params = new DHGexParameters(3072, 3072, 3072);

		assertEquals("All values should be equal", 3072, params.getMin_group_len());
		assertEquals("All values should be equal", 3072, params.getPref_group_len());
		assertEquals("All values should be equal", 3072, params.getMax_group_len());
	}

	@Test
	public void testThreeParameterConstructorBoundaryValues() {
		// Test with all boundary values
		DHGexParameters params = new DHGexParameters(1024, 4096, 8192);

		assertEquals("Min boundary should work", 1024, params.getMin_group_len());
		assertEquals("Mid value should work", 4096, params.getPref_group_len());
		assertEquals("Max boundary should work", 8192, params.getMax_group_len());
	}

	@Test
	public void testGettersReturnCorrectValues() {
		DHGexParameters params = new DHGexParameters(1536, 3072, 6144);

		// Test all getters
		assertEquals("getMin_group_len() should return correct value",
				1536, params.getMin_group_len());
		assertEquals("getPref_group_len() should return correct value",
				3072, params.getPref_group_len());
		assertEquals("getMax_group_len() should return correct value",
				6144, params.getMax_group_len());
	}

	@Test
	public void testCommonUseCaseValues() {
		// Test some common DH group sizes
		int[] commonSizes = {1024, 2048, 3072, 4096, 6144, 8192};

		for (int size : commonSizes) {
			DHGexParameters params = new DHGexParameters(size);
			assertEquals("Common size " + size + " should be valid",
					size, params.getPref_group_len());
		}
	}

	@Test
	public void testValidRangeOfValues() {
		// Test that a reasonable range of values within bounds work
		for (int min = 1024; min <= 4096; min += 1024) {
			for (int pref = min; pref <= 6144; pref += 1024) {
				for (int max = pref; max <= 8192; max += 1024) {
					DHGexParameters params = new DHGexParameters(min, pref, max);
					assertEquals("Min should match", min, params.getMin_group_len());
					assertEquals("Pref should match", pref, params.getPref_group_len());
					assertEquals("Max should match", max, params.getMax_group_len());
				}
			}
		}
	}
}
