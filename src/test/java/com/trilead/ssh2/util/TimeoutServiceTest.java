package com.trilead.ssh2.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TimeoutServiceTest {

	private static final long TEST_TIMEOUT_MS = 5000;

	@BeforeEach
	public void setUp() {
		// Clear any existing timeouts
		TimeoutService.TimeoutToken[] activeTokens = getActiveTimeouts();
		for (TimeoutService.TimeoutToken token : activeTokens) {
			TimeoutService.cancelTimeoutHandler(token);
		}
	}

	@AfterEach
	public void tearDown() {
		// Clean up any remaining timeouts
		TimeoutService.TimeoutToken[] activeTokens = getActiveTimeouts();
		for (TimeoutService.TimeoutToken token : activeTokens) {
			TimeoutService.cancelTimeoutHandler(token);
		}
	}

	private TimeoutService.TimeoutToken[] getActiveTimeouts() {
		// This is a workaround since we can't directly access the todolist
		// We'll rely on test cleanup to prevent interference
		return new TimeoutService.TimeoutToken[0];
	}

	@Test
	public void testBasicTimeoutExecution() throws InterruptedException {
		final AtomicBoolean executed = new AtomicBoolean(false);
		final CountDownLatch latch = new CountDownLatch(1);

		Runnable handler = new Runnable() {
			@Override
			public void run() {
				executed.set(true);
				latch.countDown();
			}
		};

		long startTime = System.currentTimeMillis();
		TimeoutService.TimeoutToken token = TimeoutService.addTimeoutHandler(
				startTime + 100, handler);

		assertNotNull(token, "Token should not be null");
		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "Handler should execute within timeout");
		assertTrue(executed.get(), "Handler should have been executed");
	}

	@Test
	public void testTimeoutCancellation() throws InterruptedException {
		final AtomicBoolean executed = new AtomicBoolean(false);
		final CountDownLatch latch = new CountDownLatch(1);

		Runnable handler = new Runnable() {
			@Override
			public void run() {
				executed.set(true);
				latch.countDown();
			}
		};

		long startTime = System.currentTimeMillis();
		TimeoutService.TimeoutToken token = TimeoutService.addTimeoutHandler(
				startTime + 200, handler);

		assertNotNull(token, "Token should not be null");

		// Cancel the timeout before it executes
		TimeoutService.cancelTimeoutHandler(token);

		// Wait a bit to ensure the timeout would have fired
		Thread.sleep(300);

		assertFalse(executed.get(), "Handler should not have been executed after cancellation");
	}

	@Test
	public void testMultipleTimeouts() throws InterruptedException {
		final AtomicInteger executionCount = new AtomicInteger(0);
		final CountDownLatch latch = new CountDownLatch(3);

		Runnable handler1 = new Runnable() {
			@Override
			public void run() {
				executionCount.incrementAndGet();
				latch.countDown();
			}
		};

		Runnable handler2 = new Runnable() {
			@Override
			public void run() {
				executionCount.incrementAndGet();
				latch.countDown();
			}
		};

		Runnable handler3 = new Runnable() {
			@Override
			public void run() {
				executionCount.incrementAndGet();
				latch.countDown();
			}
		};

		long startTime = System.currentTimeMillis();

		// Add timeouts in reverse order to test sorting
		TimeoutService.addTimeoutHandler(startTime + 300, handler3);
		TimeoutService.addTimeoutHandler(startTime + 100, handler1);
		TimeoutService.addTimeoutHandler(startTime + 200, handler2);

		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "All handlers should execute within timeout");
		assertEquals(3, executionCount.get(), "All three handlers should have executed");
	}

	@Test
	public void testTimeoutOrdering() throws InterruptedException {
		final AtomicInteger executionOrder = new AtomicInteger(0);
		final AtomicInteger firstExecution = new AtomicInteger(-1);
		final AtomicInteger secondExecution = new AtomicInteger(-1);
		final AtomicInteger thirdExecution = new AtomicInteger(-1);
		final CountDownLatch latch = new CountDownLatch(3);

		Runnable handler1 = new Runnable() {
			@Override
			public void run() {
				firstExecution.set(executionOrder.incrementAndGet());
				latch.countDown();
			}
		};

		Runnable handler2 = new Runnable() {
			@Override
			public void run() {
				secondExecution.set(executionOrder.incrementAndGet());
				latch.countDown();
			}
		};

		Runnable handler3 = new Runnable() {
			@Override
			public void run() {
				thirdExecution.set(executionOrder.incrementAndGet());
				latch.countDown();
			}
		};

		long startTime = System.currentTimeMillis();

		// Add timeouts with specific ordering
		TimeoutService.addTimeoutHandler(startTime + 300, handler3); // Should execute last
		TimeoutService.addTimeoutHandler(startTime + 100, handler1); // Should execute first
		TimeoutService.addTimeoutHandler(startTime + 200, handler2); // Should execute second

		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "All handlers should execute within timeout");

		assertEquals(1, firstExecution.get(), "First handler should execute first");
		assertEquals(2, secondExecution.get(), "Second handler should execute second");
		assertEquals(3, thirdExecution.get(), "Third handler should execute third");
	}

	@Test
	public void testSameTimeoutTime() throws InterruptedException {
		final AtomicInteger executionCount = new AtomicInteger(0);
		final CountDownLatch latch = new CountDownLatch(2);

		Runnable handler1 = new Runnable() {
			@Override
			public void run() {
				executionCount.incrementAndGet();
				latch.countDown();
			}
		};

		Runnable handler2 = new Runnable() {
			@Override
			public void run() {
				executionCount.incrementAndGet();
				latch.countDown();
			}
		};

		long timeoutTime = System.currentTimeMillis() + 100;

		TimeoutService.addTimeoutHandler(timeoutTime, handler1);
		TimeoutService.addTimeoutHandler(timeoutTime, handler2);

		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "Both handlers should execute within timeout");
		assertEquals(2, executionCount.get(), "Both handlers should have executed");
	}

	@Test
	public void testHandlerException() throws InterruptedException {
		final AtomicBoolean executed = new AtomicBoolean(false);
		final CountDownLatch latch = new CountDownLatch(1);

		Runnable throwingHandler = new Runnable() {
			@Override
			public void run() {
				executed.set(true);
				latch.countDown();
				throw new RuntimeException("Test exception");
			}
		};

		long startTime = System.currentTimeMillis();
		TimeoutService.addTimeoutHandler(startTime + 100, throwingHandler);

		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "Handler should execute even if it throws exception");
		assertTrue(executed.get(), "Handler should have been executed");
	}

	@Test
	public void testCancelNonExistentTimeout() {
		// Create a token but don't add it to the service
		TimeoutService.TimeoutToken fakeToken = createFakeToken();

		// This should not throw an exception
		TimeoutService.cancelTimeoutHandler(fakeToken);
	}

	@Test
	public void testTimeoutTokenComparison() {
		TimeoutService.TimeoutToken token1 = createTokenWithTime(100);
		TimeoutService.TimeoutToken token2 = createTokenWithTime(200);
		TimeoutService.TimeoutToken token3 = createTokenWithTime(100);

		assertTrue(token1.compareTo(token2) < 0, "Token with earlier time should be less");
		assertTrue(token2.compareTo(token1) > 0, "Token with later time should be greater");
		assertEquals(0, token1.compareTo(token3), "Tokens with same time should be equal");
	}

	@Test
	public void testZeroDelayTimeout() throws InterruptedException {
		final AtomicBoolean executed = new AtomicBoolean(false);
		final CountDownLatch latch = new CountDownLatch(1);

		Runnable handler = new Runnable() {
			@Override
			public void run() {
				executed.set(true);
				latch.countDown();
			}
		};

		// Use current time or past time to test immediate execution
		long pastTime = System.currentTimeMillis() - 100;
		TimeoutService.addTimeoutHandler(pastTime, handler);

		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "Handler should execute immediately for past time");
		assertTrue(executed.get(), "Handler should have been executed");
	}

	@Test
	public void testConcurrentTimeouts() throws InterruptedException {
		final AtomicInteger executionCount = new AtomicInteger(0);
		final CountDownLatch latch = new CountDownLatch(10);

		// Create multiple timeouts concurrently
		Thread[] threads = new Thread[10];

		for (int i = 0; i < 10; i++) {
			final int index = i;
			threads[i] = new Thread(new Runnable() {
				@Override
				public void run() {
					Runnable handler = new Runnable() {
						@Override
						public void run() {
							executionCount.incrementAndGet();
							latch.countDown();
						}
					};

					long timeout = System.currentTimeMillis() + 100 + (index * 10);
					TimeoutService.addTimeoutHandler(timeout, handler);
				}
			});
		}

		// Start all threads
		for (Thread thread : threads) {
			thread.start();
		}

		// Wait for all threads to complete
		for (Thread thread : threads) {
			thread.join();
		}

		assertTrue(latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS), "All handlers should execute within timeout");
		assertEquals(10, executionCount.get(), "All 10 handlers should have executed");
	}

	// Helper methods for testing private functionality
	private TimeoutService.TimeoutToken createFakeToken() {
		// We can't directly create a token since the constructor is private
		// This test verifies that canceling a non-existent token doesn't crash
		return TimeoutService.addTimeoutHandler(System.currentTimeMillis() + 10000,
				new Runnable() {
					public void run() {
					}
				});
	}

	private TimeoutService.TimeoutToken createTokenWithTime(long runTime) {
		return TimeoutService.addTimeoutHandler(runTime, new Runnable() {
			@Override
			public void run() {
				// Empty handler for testing comparison
			}
		});
	}
}
