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
}
