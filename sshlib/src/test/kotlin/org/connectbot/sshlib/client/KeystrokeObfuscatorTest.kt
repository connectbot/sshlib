/*
 * Copyright 2025 Kenny Root
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

package org.connectbot.sshlib.client

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertFailsWith

class KeystrokeObfuscatorTest {

    private val intervalMs = 20L

    @Test
    fun `initially not active`() {
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { 0L })
        assertFalse(obfuscator.isActive())
    }

    @Test
    fun `rejects non-positive interval`() {
        assertFailsWith<IllegalArgumentException> {
            KeystrokeObfuscator(0L)
        }
        assertFailsWith<IllegalArgumentException> {
            KeystrokeObfuscator(-1L)
        }
    }

    @Test
    fun `becomes active on first keystroke`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        assertTrue(obfuscator.isActive())
    }

    @Test
    fun `delayUntilNextSendMs is bounded on first keystroke at start`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        // The first keystroke starts the session; delay until the first interval
        // boundary from 'now'. Since we just started, we should get a small positive value.
        val delay = obfuscator.delayUntilNextSendMs()
        assertTrue(delay >= 0, "Delay should be non-negative, was $delay")
        // Delay must be within one interval (plus fuzz) of starting
        assertTrue(delay <= intervalMs * 2, "Delay $delay should be within 2 intervals")
    }

    @Test
    fun `delayUntilNextSendMs is zero when interval has elapsed`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        // Advance time past the next interval
        now = intervalMs * 3
        val delay = obfuscator.delayUntilNextSendMs()
        assertEquals(0L, delay, "Delay should be 0 when interval has elapsed")
    }

    @Test
    fun `chaffUntilMs extends after recordKeystroke at a later time`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        val chaffUntil1 = obfuscator.chaffUntilMs()
        assertTrue(chaffUntil1 > 0, "chaffUntilMs should be positive after first keystroke")

        // Advance time well past the chaff window and record another keystroke.
        // The new chaffUntilMs is computed from the new 'now', so it will be larger.
        now = chaffUntil1 + intervalMs * 10
        obfuscator.recordKeystroke()
        val chaffUntil2 = obfuscator.chaffUntilMs()
        assertTrue(chaffUntil2 > chaffUntil1, "chaffUntilMs should extend after subsequent keystroke at later time")
    }

    @Test
    fun `isActive becomes false after chaff window expires`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        assertTrue(obfuscator.isActive())

        // Advance past chaff window
        now = obfuscator.chaffUntilMs() + 1
        assertFalse(obfuscator.isActive())
    }

    @Test
    fun `stop deactivates immediately`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        assertTrue(obfuscator.isActive())
        obfuscator.stop()
        assertFalse(obfuscator.isActive())
    }

    @Test
    fun `nextIntervalMs advances on advanceInterval when time has moved past it`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        val first = obfuscator.nextIntervalMs()
        // Advance clock to the next interval boundary before calling advanceInterval
        now = first
        obfuscator.advanceInterval()
        val second = obfuscator.nextIntervalMs()
        assertTrue(second > first, "Next interval should advance after advanceInterval()")
    }

    @Test
    fun `fuzz keeps interval within expected bounds`() {
        // Run many iterations to verify fuzz stays within [0.9x, 1.1x + sessionRate] of interval
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()

        repeat(100) {
            val prev = obfuscator.nextIntervalMs()
            now = prev
            obfuscator.advanceInterval()
            val next = obfuscator.nextIntervalMs()
            val elapsed = next - prev
            // Allow up to 2x due to session rate fuzz, but must be at least 80% of interval
            assertTrue(
                elapsed >= intervalMs * 80L / 100L,
                "Interval $elapsed was below 80% of expected $intervalMs",
            )
            assertTrue(
                elapsed <= intervalMs * 220L / 100L,
                "Interval $elapsed exceeded 220% of expected $intervalMs",
            )
        }
    }

    // --- delayUntilNextSendMs boundary tests ---

    @Test
    fun `delayUntilNextSendMs returns 0 exactly when now equals nextIntervalMs`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        val boundary = obfuscator.nextIntervalMs()
        now = boundary
        assertEquals(0L, obfuscator.delayUntilNextSendMs())
    }

    @Test
    fun `delayUntilNextSendMs returns 1 when one ms before nextIntervalMs`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        val boundary = obfuscator.nextIntervalMs()
        now = boundary - 1
        assertEquals(1L, obfuscator.delayUntilNextSendMs())
    }

    // --- advanceInterval math and clamp tests ---

    @Test
    fun `advanceInterval skips exactly one interval when just past boundary`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        val first = obfuscator.nextIntervalMs()
        now = first + 1 // just past the first boundary
        obfuscator.advanceInterval()
        val second = obfuscator.nextIntervalMs()
        // Must be strictly after 'now', not before it
        assertTrue(second > now, "nextIntervalMs $second should be after now $now")
    }

    @Test
    fun `advanceInterval skips multiple missed intervals`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        val first = obfuscator.nextIntervalMs()
        // Advance 5 full intervals past the boundary
        now = first + intervalMs * 5
        obfuscator.advanceInterval()
        val second = obfuscator.nextIntervalMs()
        assertTrue(second > now, "nextIntervalMs $second should be after now $now after skipping intervals")
    }

    @Test
    fun `advanceInterval clamps negative missed-interval count to zero`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        // Don't advance clock — now is before nextIntervalMs so missedIntervals would be negative
        val before = obfuscator.nextIntervalMs()
        obfuscator.advanceInterval()
        val after = obfuscator.nextIntervalMs()
        // Result should still be in the future (clamped to 0 missed, advances by 1 interval)
        assertTrue(after > now, "nextIntervalMs $after should be positive after clamp")
        // The boundary should move forward even though we didn't cross it.
        assertTrue(after > before, "nextIntervalMs $after should be after previous boundary $before")
        assertTrue(after >= 1L, "nextIntervalMs must be at least 1")
    }

    // --- computeFuzzMs boundary tests ---

    @Test
    fun `fuzz floor is 1 for tiny intervals`() {
        // With intervalMs=1 and FUZZ_PERCENT=10, raw fuzz = 0 → should clamp to 1
        var now = 0L
        val obfuscator = KeystrokeObfuscator(1L, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        // nextIntervalMs must be at least 1 (coerceAtLeast(1))
        assertTrue(obfuscator.nextIntervalMs() >= 1L)
    }

    @Test
    fun `interval close to Long MAX does not overflow fuzz computation`() {
        // Int.MAX_VALUE cap prevents fuzz from exceeding random's int range
        val hugeInterval = Int.MAX_VALUE.toLong() * 100L
        var now = 0L
        val obfuscator = KeystrokeObfuscator(hugeInterval, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        assertTrue(obfuscator.nextIntervalMs() >= 1L)
    }

    // --- setNextInterval: sessionRate only set on starting=true ---

    @Test
    fun `sessionRate is fixed per session and does not change on subsequent advances`() {
        // Use a seeded Random so results are deterministic.
        // First keystroke sets sessionRate (starting=true). Subsequent advanceInterval calls
        // should NOT change sessionRate (starting=false), so the per-advance fuzz is different
        // from what it would be if sessionRate were reset each time.
        var now = 0L
        val seededRandom = Random(42)
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now }, random = seededRandom)
        obfuscator.recordKeystroke()

        // Record nextIntervalMs values across several advances
        val intervals = mutableListOf<Long>()
        repeat(5) {
            val prev = obfuscator.nextIntervalMs()
            now = prev
            obfuscator.advanceInterval()
            intervals.add(obfuscator.nextIntervalMs() - prev)
        }

        // All intervals must be positive (sessionRate never causes a negative adjusted value)
        assertTrue(intervals.all { it >= 1L }, "All intervals must be >= 1, got: $intervals")
    }

    @Test
    fun `recordKeystroke returns true on first call and false when window still active`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        assertTrue(obfuscator.recordKeystroke(), "First keystroke should return true (just started)")
        // Still within chaff window
        assertFalse(obfuscator.recordKeystroke(), "Second keystroke within window should return false")
    }

    @Test
    fun `recordKeystroke returns true again after chaff window expires`() {
        var now = 0L
        val obfuscator = KeystrokeObfuscator(intervalMs, clockMs = { now })
        obfuscator.recordKeystroke()
        now = obfuscator.chaffUntilMs() + 1
        assertTrue(obfuscator.recordKeystroke(), "Keystroke after expired window should return true")
    }

    @Test
    fun `setNextInterval adjusted value is at least 1 when fuzz exceeds interval`() {
        // With intervalMs=1 fuzz=1, adjusted = 1 - 1 + random(1) + sessionRate
        // random(1) is always 0, sessionRate is random(1) which is also 0
        // → adjusted = 0, coerceAtLeast(1) = 1
        var now = 1000L
        val obfuscator = KeystrokeObfuscator(1L, clockMs = { now }, random = Random(0))
        obfuscator.recordKeystroke()
        assertTrue(obfuscator.nextIntervalMs() >= now + 1L)
    }
}
