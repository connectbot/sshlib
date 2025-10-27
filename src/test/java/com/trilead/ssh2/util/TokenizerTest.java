package com.trilead.ssh2.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class TokenizerTest {

	@Test
	public void testBasicTokenization() {
		String source = "apple,banana,cherry";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("apple", result[0], "First token should be 'apple'");
		assertEquals("banana", result[1], "Second token should be 'banana'");
		assertEquals("cherry", result[2], "Third token should be 'cherry'");
	}

	@Test
	public void testSingleToken() {
		String source = "singletoken";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(1, result.length, "Should have 1 token");
		assertEquals("singletoken", result[0], "Token should be 'singletoken'");
	}

	@Test
	public void testEmptyString() {
		String source = "";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(0, result.length, "Should return empty array for empty string");
	}

	@Test
	public void testEmptyTokens() {
		String source = ",,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 empty tokens");
		assertEquals("", result[0], "First token should be empty");
		assertEquals("", result[1], "Second token should be empty");
		assertEquals("", result[2], "Third token should be empty");
	}

	@Test
	public void testMixedEmptyAndNonEmptyTokens() {
		String source = "apple,,cherry,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(4, result.length, "Should have 4 tokens");
		assertEquals("apple", result[0], "First token should be 'apple'");
		assertEquals("", result[1], "Second token should be empty");
		assertEquals("cherry", result[2], "Third token should be 'cherry'");
		assertEquals("", result[3], "Fourth token should be empty");
	}

	@Test
	public void testLeadingDelimiter() {
		String source = ",apple,banana";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("", result[0], "First token should be empty");
		assertEquals("apple", result[1], "Second token should be 'apple'");
		assertEquals("banana", result[2], "Third token should be 'banana'");
	}

	@Test
	public void testTrailingDelimiter() {
		String source = "apple,banana,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("apple", result[0], "First token should be 'apple'");
		assertEquals("banana", result[1], "Second token should be 'banana'");
		assertEquals("", result[2], "Third token should be empty");
	}

	@Test
	public void testOnlyDelimiters() {
		String source = ",,,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(4, result.length, "Should have 4 empty tokens");
		for (int i = 0; i < result.length; i++) {
			assertEquals("", result[i], "Token " + i + " should be empty");
		}
	}

	@Test
	public void testDifferentDelimiters() {
		// Test with semicolon
		String source = "one;two;three";
		char delimiter = ';';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("one", result[0], "First token should be 'one'");
		assertEquals("two", result[1], "Second token should be 'two'");
		assertEquals("three", result[2], "Third token should be 'three'");
	}

	@Test
	public void testSpaceDelimiter() {
		String source = "hello world test";
		char delimiter = ' ';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("hello", result[0], "First token should be 'hello'");
		assertEquals("world", result[1], "Second token should be 'world'");
		assertEquals("test", result[2], "Third token should be 'test'");
	}

	@Test
	public void testTabDelimiter() {
		String source = "column1\tcolumn2\tcolumn3";
		char delimiter = '\t';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("column1", result[0], "First token should be 'column1'");
		assertEquals("column2", result[1], "Second token should be 'column2'");
		assertEquals("column3", result[2], "Third token should be 'column3'");
	}

	@Test
	public void testPipeDelimiter() {
		String source = "field1|field2|field3";
		char delimiter = '|';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("field1", result[0], "First token should be 'field1'");
		assertEquals("field2", result[1], "Second token should be 'field2'");
		assertEquals("field3", result[2], "Third token should be 'field3'");
	}

	@Test
	public void testNoDelimiterPresent() {
		String source = "nodelmiterhere";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(1, result.length, "Should have 1 token");
		assertEquals("nodelmiterhere", result[0], "Token should be the entire string");
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

		assertEquals(100, result.length, "Should have 100 tokens");
		for (int i = 0; i < 100; i++) {
			assertEquals("token" + i, result[i], "Token " + i + " should match");
		}
	}

	@Test
	public void testTokensWithWhitespace() {
		String source = " apple , banana , cherry ";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals(" apple ", result[0], "First token should include leading space");
		assertEquals(" banana ", result[1], "Second token should include spaces");
		assertEquals(" cherry ", result[2], "Third token should include trailing space");
	}

	@Test
	public void testSpecialCharactersInTokens() {
		String source = "token@with#special$chars,normal,!@#$%^&*()";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("token@with#special$chars", result[0], "First token should contain special chars");
		assertEquals("normal", result[1], "Second token should be 'normal'");
		assertEquals("!@#$%^&*()", result[2], "Third token should be special chars");
	}

	@Test
	public void testUnicodeCharacters() {
		String source = "αβγ,δεζ,ηθι";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("αβγ", result[0], "First token should be 'αβγ'");
		assertEquals("δεζ", result[1], "Second token should be 'δεζ'");
		assertEquals("ηθι", result[2], "Third token should be 'ηθι'");
	}

	@Test
	public void testNumericTokens() {
		String source = "123,456.789,-42,0";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(4, result.length, "Should have 4 tokens");
		assertEquals("123", result[0], "First token should be '123'");
		assertEquals("456.789", result[1], "Second token should be '456.789'");
		assertEquals("-42", result[2], "Third token should be '-42'");
		assertEquals("0", result[3], "Fourth token should be '0'");
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

		assertEquals(2, result.length, "Should have 2 tokens");
		assertEquals(10000, result[0].length(), "First token should be very long");
		assertEquals("short", result[1], "Second token should be 'short'");
	}

	@Test
	public void testMultipleConsecutiveDelimiters() {
		String source = "a,,,,b";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(5, result.length, "Should have 5 tokens");
		assertEquals("a", result[0], "First token should be 'a'");
		assertEquals("", result[1], "Second token should be empty");
		assertEquals("", result[2], "Third token should be empty");
		assertEquals("", result[3], "Fourth token should be empty");
		assertEquals("b", result[4], "Fifth token should be 'b'");
	}

	@Test
	public void testEdgeCaseDelimiters() {
		// Test with newline delimiter
		String source = "line1\nline2\nline3";
		char delimiter = '\n';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("line1", result[0], "First token should be 'line1'");
		assertEquals("line2", result[1], "Second token should be 'line2'");
		assertEquals("line3", result[2], "Third token should be 'line3'");
	}

	@Test
	public void testDelimiterAtEachPosition() {
		// Test delimiter at start, middle, and end
		String source = ",middle,";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(3, result.length, "Should have 3 tokens");
		assertEquals("", result[0], "First token should be empty");
		assertEquals("middle", result[1], "Second token should be 'middle'");
		assertEquals("", result[2], "Third token should be empty");
	}

	@Test
	public void testPathLikeString() {
		// Test parsing path-like strings
		String source = "/usr/local/bin";
		char delimiter = '/';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(4, result.length, "Should have 4 tokens");
		assertEquals("", result[0], "First token should be empty (root)");
		assertEquals("usr", result[1], "Second token should be 'usr'");
		assertEquals("local", result[2], "Third token should be 'local'");
		assertEquals("bin", result[3], "Fourth token should be 'bin'");
	}

	@Test
	public void testCSVLikeString() {
		// Test parsing CSV-like data
		String source = "John Doe,30,Engineer,New York";
		char delimiter = ',';
		String[] result = Tokenizer.parseTokens(source, delimiter);

		assertEquals(4, result.length, "Should have 4 tokens");
		assertEquals("John Doe", result[0], "First token should be 'John Doe'");
		assertEquals("30", result[1], "Second token should be '30'");
		assertEquals("Engineer", result[2], "Third token should be 'Engineer'");
		assertEquals("New York", result[3], "Fourth token should be 'New York'");
	}
}
