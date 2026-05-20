/*
 * ConnectBot SSH Library
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

package org.connectbot.sshlib

import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StreamForwarderTest {

    @Test
    fun `close delegates to stop`() {
        var stopCalled = false
        val forwarder = object : StreamForwarder {
            override val isActive: Boolean get() = !stopCalled
            override suspend fun stop() {
                stopCalled = true
            }
        }

        assertTrue(forwarder.isActive)
        forwarder.close()
        assertTrue(stopCalled)
        assertFalse(forwarder.isActive)
    }
}
