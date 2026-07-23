/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

import org.connectbot.sshlib.protocol.SshEnums
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SshConnectionPacketClassificationTest {
    @Test
    fun `only transport key exchange messages bypass the strict kex gate`() {
        assertTrue(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_KEXINIT.id().toInt()))
        assertTrue(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt()))
        assertTrue(isKeyExchangeMessage(30))
        assertTrue(isKeyExchangeMessage(49))

        assertFalse(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt()))
        assertFalse(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_DEBUG.id().toInt()))
        assertFalse(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_EXT_INFO.id().toInt()))
        assertFalse(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_SERVICE_ACCEPT.id().toInt()))
        assertFalse(isKeyExchangeMessage(SshEnums.MessageType.SSH_MSG_DISCONNECT.id().toInt()))
        assertFalse(isKeyExchangeMessage(29))
        assertFalse(isKeyExchangeMessage(50))
    }
}
