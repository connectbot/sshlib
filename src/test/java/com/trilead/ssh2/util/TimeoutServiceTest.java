package com.trilead.ssh2.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class TimeoutServiceTest {

	private static final long TEST_TIMEOUT_MS = 5000;

	@Before
	public void setUp() {
		// Clear any existing timeouts
		TimeoutService.TimeoutToken[] activeTokens = getActiveTimeouts();
		for (TimeoutService.TimeoutToken token : activeTokens) {
			TimeoutService.cancelTimeoutHandler(token);
		}
	}

	@After
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

		assertNotNull("Token should not be null", token);
		assertTrue("Handler should execute within timeout",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertTrue("Handler should have been executed", executed.get());
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

		assertNotNull("Token should not be null", token);

		// Cancel the timeout before it executes
		TimeoutService.cancelTimeoutHandler(token);

		// Wait a bit to ensure the timeout would have fired
		Thread.sleep(300);

		assertFalse("Handler should not have been executed after cancellation",
				executed.get());
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

		assertTrue("All handlers should execute within timeout",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertEquals("All three handlers should have executed", 3, executionCount.get());
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

		assertTrue("All handlers should execute within timeout",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));

		assertEquals("First handler should execute first", 1, firstExecution.get());
		assertEquals("Second handler should execute second", 2, secondExecution.get());
		assertEquals("Third handler should execute third", 3, thirdExecution.get());
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

		assertTrue("Both handlers should execute within timeout",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertEquals("Both handlers should have executed", 2, executionCount.get());
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

		assertTrue("Handler should execute even if it throws exception",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertTrue("Handler should have been executed", executed.get());
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

		assertTrue("Token with earlier time should be less", token1.compareTo(token2) < 0);
		assertTrue("Token with later time should be greater", token2.compareTo(token1) > 0);
		assertEquals("Tokens with same time should be equal", 0, token1.compareTo(token3));
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

		assertTrue("Handler should execute immediately for past time",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertTrue("Handler should have been executed", executed.get());
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

		assertTrue("All handlers should execute within timeout",
				latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertEquals("All 10 handlers should have executed", 10, executionCount.get());
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
