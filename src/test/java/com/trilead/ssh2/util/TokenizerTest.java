package com.trilead.ssh2.util;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TokenizerTest {

	@Test
	public void testBasicTokenization() {
		String source = "apple,banana,cherry";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'apple'", "apple", result[0]);
		assertEquals("Second token should be 'banana'", "banana", result[1]);
		assertEquals("Third token should be 'cherry'", "cherry", result[2]);
	}

	@Test
	public void testSingleToken() {
		String source = "singletoken";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 1 token", 1, result.length);
		assertEquals("Token should be 'singletoken'", "singletoken", result[0]);
	}

	@Test
	public void testEmptyString() {
		String source = "";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should return empty array for empty string", 0, result.length);
	}

	@Test
	public void testEmptyTokens() {
		String source = ",,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 empty tokens", 3, result.length);
		assertEquals("First token should be empty", "", result[0]);
		assertEquals("Second token should be empty", "", result[1]);
		assertEquals("Third token should be empty", "", result[2]);
	}

	@Test
	public void testMixedEmptyAndNonEmptyTokens() {
		String source = "apple,,cherry,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 4 tokens", 4, result.length);
		assertEquals("First token should be 'apple'", "apple", result[0]);
		assertEquals("Second token should be empty", "", result[1]);
		assertEquals("Third token should be 'cherry'", "cherry", result[2]);
		assertEquals("Fourth token should be empty", "", result[3]);
	}

	@Test
	public void testLeadingDelimiter() {
		String source = ",apple,banana";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be empty", "", result[0]);
		assertEquals("Second token should be 'apple'", "apple", result[1]);
		assertEquals("Third token should be 'banana'", "banana", result[2]);
	}

	@Test
	public void testTrailingDelimiter() {
		String source = "apple,banana,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'apple'", "apple", result[0]);
		assertEquals("Second token should be 'banana'", "banana", result[1]);
		assertEquals("Third token should be empty", "", result[2]);
	}

	@Test
	public void testOnlyDelimiters() {
		String source = ",,,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 4 empty tokens", 4, result.length);
		for (int i = 0; i < result.length; i++) {
			assertEquals("Token " + i + " should be empty", "", result[i]);
		}
	}

	@Test
	public void testDifferentDelimiters() {
		// Test with semicolon
		String source = "one;two;three";
		char delimiter = ';';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'one'", "one", result[0]);
		assertEquals("Second token should be 'two'", "two", result[1]);
		assertEquals("Third token should be 'three'", "three", result[2]);
	}

	@Test
	public void testSpaceDelimiter() {
		String source = "hello world test";
		char delimiter = ' ';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'hello'", "hello", result[0]);
		assertEquals("Second token should be 'world'", "world", result[1]);
		assertEquals("Third token should be 'test'", "test", result[2]);
	}

	@Test
	public void testTabDelimiter() {
		String source = "column1\tcolumn2\tcolumn3";
		char delimiter = '\t';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'column1'", "column1", result[0]);
		assertEquals("Second token should be 'column2'", "column2", result[1]);
		assertEquals("Third token should be 'column3'", "column3", result[2]);
	}

	@Test
	public void testPipeDelimiter() {
		String source = "field1|field2|field3";
		char delimiter = '|';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'field1'", "field1", result[0]);
		assertEquals("Second token should be 'field2'", "field2", result[1]);
		assertEquals("Third token should be 'field3'", "field3", result[2]);
	}

	@Test
	public void testNoDelimiterPresent() {
		String source = "nodelmiterhere";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 1 token", 1, result.length);
		assertEquals("Token should be the entire string", "nodelmiterhere", result[0]);
	}

	@Test
	public void testLongString() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 100; i++) {
			if (i > 0)
				sb.append(",");
			sb.append("token").append(i);
		}

		String source = sb.toString();
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 100 tokens", 100, result.length);
		for (int i = 0; i < 100; i++) {
			assertEquals("Token " + i + " should match", "token" + i, result[i]);
		}
	}

	@Test
	public void testTokensWithWhitespace() {
		String source = " apple , banana , cherry ";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should include leading space", " apple ", result[0]);
		assertEquals("Second token should include spaces", " banana ", result[1]);
		assertEquals("Third token should include trailing space", " cherry ", result[2]);
	}

	@Test
	public void testSpecialCharactersInTokens() {
		String source = "token@with#special$chars,normal,!@#$%^&*()";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should contain special chars", "token@with#special$chars", result[0]);
		assertEquals("Second token should be 'normal'", "normal", result[1]);
		assertEquals("Third token should be special chars", "!@#$%^&*()", result[2]);
	}

	@Test
	public void testUnicodeCharacters() {
		String source = "αβγ,δεζ,ηθι";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'αβγ'", "αβγ", result[0]);
		assertEquals("Second token should be 'δεζ'", "δεζ", result[1]);
		assertEquals("Third token should be 'ηθι'", "ηθι", result[2]);
	}

	@Test
	public void testNumericTokens() {
		String source = "123,456.789,-42,0";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 4 tokens", 4, result.length);
		assertEquals("First token should be '123'", "123", result[0]);
		assertEquals("Second token should be '456.789'", "456.789", result[1]);
		assertEquals("Third token should be '-42'", "-42", result[2]);
		assertEquals("Fourth token should be '0'", "0", result[3]);
	}

	@Test
	public void testVeryLongToken() {
		StringBuilder longToken = new StringBuilder();
		for (int i = 0; i < 10000; i++) {
			longToken.append('a');
		}

		String source = longToken.toString() + ",short";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 2 tokens", 2, result.length);
		assertEquals("First token should be very long", 10000, result[0].length());
		assertEquals("Second token should be 'short'", "short", result[1]);
	}

	@Test
	public void testMultipleConsecutiveDelimiters() {
		String source = "a,,,,b";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 5 tokens", 5, result.length);
		assertEquals("First token should be 'a'", "a", result[0]);
		assertEquals("Second token should be empty", "", result[1]);
		assertEquals("Third token should be empty", "", result[2]);
		assertEquals("Fourth token should be empty", "", result[3]);
		assertEquals("Fifth token should be 'b'", "b", result[4]);
	}

	@Test
	public void testEdgeCaseDelimiters() {
		// Test with newline delimiter
		String source = "line1\nline2\nline3";
		char delimiter = '\n';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be 'line1'", "line1", result[0]);
		assertEquals("Second token should be 'line2'", "line2", result[1]);
		assertEquals("Third token should be 'line3'", "line3", result[2]);
	}

	@Test
	public void testDelimiterAtEachPosition() {
		// Test delimiter at start, middle, and end
		String source = ",middle,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 3 tokens", 3, result.length);
		assertEquals("First token should be empty", "", result[0]);
		assertEquals("Second token should be 'middle'", "middle", result[1]);
		assertEquals("Third token should be empty", "", result[2]);
	}

	@Test
	public void testPathLikeString() {
		// Test parsing path-like strings
		String source = "/usr/local/bin";
		char delimiter = '/';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 4 tokens", 4, result.length);
		assertEquals("First token should be empty (root)", "", result[0]);
		assertEquals("Second token should be 'usr'", "usr", result[1]);
		assertEquals("Third token should be 'local'", "local", result[2]);
		assertEquals("Fourth token should be 'bin'", "bin", result[3]);
	}

	@Test
	public void testCSVLikeString() {
		// Test parsing CSV-like data
		String source = "John Doe,30,Engineer,New York";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals("Should have 4 tokens", 4, result.length);
		assertEquals("First token should be 'John Doe'", "John Doe", result[0]);
		assertEquals("Second token should be '30'", "30", result[1]);
		assertEquals("Third token should be 'Engineer'", "Engineer", result[2]);
		assertEquals("Fourth token should be 'New York'", "New York", result[3]);
	}
}
