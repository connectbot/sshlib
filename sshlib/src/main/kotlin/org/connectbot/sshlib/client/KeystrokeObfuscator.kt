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

import kotlin.random.Random

/**
 * Tracks timing state for keystroke obfuscation in interactive SSH sessions.
 *
 * Mirrors the algorithm in OpenSSH clientloop.c `obfuscate_keystroke_timing()` /
 * `set_next_interval()`. Pure timing logic with no coroutine dependencies so it can be
 * unit-tested directly.
 *
 * Chaff packets (SSH_MSG_PING) are sent between real keystrokes to fill timing gaps. The
 * interval is fuzzed per-packet and a per-session rate offset is applied to make the average
 * rate unpredictable.
 */
internal class KeystrokeObfuscator(
    private val intervalMs: Long,
    private val clockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    private val random: Random = Random.Default,
) {
    init {
        require(intervalMs > 0) { "intervalMs must be greater than 0" }
    }

    companion object {
        private const val FUZZ_PERCENT = 10L
        private const val CHAFF_MIN_MS = 100L
        private const val CHAFF_RANGE_MS = 400L
    }

    private var active = false
    private var nextIntervalMs = 0L
    private var _chaffUntilMs = 0L

    // Per-session constant fuzz offset, set once when obfuscation starts.
    private var sessionRate = 0L

    fun isActive(): Boolean = active && clockMs() < _chaffUntilMs

    fun chaffUntilMs(): Long = _chaffUntilMs

    fun nextIntervalMs(): Long = nextIntervalMs

    fun stop() {
        active = false
    }

    /**
     * Record a real keystroke.
     *
     * @return true when this keystroke started or restarted an obfuscation window.
     */
    fun recordKeystroke(): Boolean {
        val now = clockMs()
        val justStarted = !active || now >= _chaffUntilMs
        if (justStarted) {
            active = true
            setNextInterval(now, intervalMs, starting = true)
        }
        _chaffUntilMs = now + CHAFF_MIN_MS + random.nextLong(CHAFF_RANGE_MS)
        return justStarted
    }

    /** Returns milliseconds to wait before the next send is allowed (0 if ready now). */
    fun delayUntilNextSendMs(): Long {
        val now = clockMs()
        if (now >= nextIntervalMs) return 0L
        return nextIntervalMs - now
    }

    /** Advance [nextIntervalMs] to the next boundary, accounting for missed intervals. */
    fun advanceInterval() {
        val now = clockMs()
        var missedIntervals = (now - nextIntervalMs) / intervalMs
        if (missedIntervals < 0) missedIntervals = 0
        setNextInterval(now, intervalMs * (missedIntervals + 1), starting = false)
    }

    private fun computeFuzzMs(intervalMsValue: Long): Long {
        var fuzz = intervalMsValue * FUZZ_PERCENT / 100L
        if (fuzz <= 0L) fuzz = 1L
        if (fuzz > Int.MAX_VALUE) fuzz = Int.MAX_VALUE.toLong()
        return fuzz
    }

    private fun setNextInterval(now: Long, intervalMsValue: Long, starting: Boolean) {
        val fuzz = computeFuzzMs(intervalMsValue)
        if (starting) sessionRate = random.nextLong(fuzz)
        val adjusted = intervalMsValue - fuzz + random.nextLong(fuzz) + sessionRate
        nextIntervalMs = now + adjusted.coerceAtLeast(1L)
    }
}
