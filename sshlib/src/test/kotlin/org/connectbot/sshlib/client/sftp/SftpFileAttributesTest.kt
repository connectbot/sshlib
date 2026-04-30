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

package org.connectbot.sshlib.client.sftp

import org.connectbot.sshlib.SftpAttributes
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SftpFileAttributesTest {

    private fun roundTrip(attrs: SftpAttributes): SftpAttributes {
        val encoded = SftpFileAttributes.encode(attrs)
        return SftpFileAttributes.decode(ByteBuffer.wrap(encoded))
    }

    @Test
    fun `empty attributes encodes to just flags field`() {
        val encoded = SftpFileAttributes.encode(SftpAttributes.EMPTY)
        assertEquals(4, encoded.size)
        assertEquals(0, ByteBuffer.wrap(encoded).int)
    }

    @Test
    fun `size roundtrip`() {
        val attrs = SftpAttributes(size = 1234567890L)
        val result = roundTrip(attrs)
        assertEquals(1234567890L, result.size)
        assertNull(result.uid)
        assertNull(result.gid)
        assertNull(result.permissions)
    }

    @Test
    fun `uid and gid roundtrip`() {
        val attrs = SftpAttributes(uid = 1000, gid = 1001)
        val result = roundTrip(attrs)
        assertEquals(1000, result.uid)
        assertEquals(1001, result.gid)
        assertNull(result.size)
    }

    @Test
    fun `uid without gid still sets uidgid flag`() {
        val attrs = SftpAttributes(uid = 500)
        val result = roundTrip(attrs)
        assertEquals(500, result.uid)
        assertEquals(0, result.gid)
    }

    @Test
    fun `gid without uid still sets uidgid flag`() {
        val attrs = SftpAttributes(gid = 500)
        val result = roundTrip(attrs)
        assertEquals(0, result.uid)
        assertEquals(500, result.gid)
    }

    @Test
    fun `permissions roundtrip`() {
        val perms = 0b1_000_000_110_100_100
        val attrs = SftpAttributes(permissions = perms)
        val result = roundTrip(attrs)
        assertEquals(perms, result.permissions)
    }

    @Test
    fun `atime and mtime roundtrip`() {
        val attrs = SftpAttributes(atime = 1000000, mtime = 2000000)
        val result = roundTrip(attrs)
        assertEquals(1000000, result.atime)
        assertEquals(2000000, result.mtime)
    }

    @Test
    fun `atime without mtime sets acmodtime flag`() {
        val attrs = SftpAttributes(atime = 999)
        val result = roundTrip(attrs)
        assertEquals(999, result.atime)
        assertEquals(0, result.mtime)
    }

    @Test
    fun `mtime without atime sets acmodtime flag`() {
        val attrs = SftpAttributes(mtime = 999)
        val result = roundTrip(attrs)
        assertEquals(0, result.atime)
        assertEquals(999, result.mtime)
    }

    @Test
    fun `all fields roundtrip`() {
        val attrs = SftpAttributes(
            size = 999L,
            uid = 42,
            gid = 43,
            permissions = 0b111_101_101,
            atime = 1000,
            mtime = 2000,
        )
        val result = roundTrip(attrs)
        assertEquals(attrs, result)
    }

    @Test
    fun `size flag is bit 0`() {
        val encoded = SftpFileAttributes.encode(SftpAttributes(size = 1L))
        val flags = ByteBuffer.wrap(encoded).int
        assertEquals(1, flags and 0x00000001)
    }

    @Test
    fun `uidgid flag is bit 1`() {
        val encoded = SftpFileAttributes.encode(SftpAttributes(uid = 1))
        val flags = ByteBuffer.wrap(encoded).int
        assertEquals(2, flags and 0x00000002)
    }

    @Test
    fun `permissions flag is bit 2`() {
        val encoded = SftpFileAttributes.encode(SftpAttributes(permissions = 0b111_101_101))
        val flags = ByteBuffer.wrap(encoded).int
        assertEquals(4, flags and 0x00000004)
    }

    @Test
    fun `acmodtime flag is bit 3`() {
        val encoded = SftpFileAttributes.encode(SftpAttributes(atime = 1))
        val flags = ByteBuffer.wrap(encoded).int
        assertEquals(8, flags and 0x00000008)
    }

    @Test
    fun `decode with only size flag present`() {
        // Manually craft: flags=0x01, size=0x0000000000000064 (100)
        val buf = ByteBuffer.allocate(12)
        buf.putInt(0x00000001)
        buf.putLong(100L)
        buf.flip()
        val attrs = SftpFileAttributes.decode(buf)
        assertEquals(100L, attrs.size)
        assertNull(attrs.uid)
        assertNull(attrs.permissions)
    }

    @Test
    fun `decode with no flags sets all fields to null`() {
        val buf = ByteBuffer.allocate(4)
        buf.putInt(0)
        buf.flip()
        val attrs = SftpFileAttributes.decode(buf)
        assertNull(attrs.size)
        assertNull(attrs.uid)
        assertNull(attrs.gid)
        assertNull(attrs.permissions)
        assertNull(attrs.atime)
        assertNull(attrs.mtime)
    }

    @Test
    fun `encoded size for all fields is correct`() {
        val attrs = SftpAttributes(
            size = 1L,
            uid = 1,
            gid = 1,
            permissions = 1,
            atime = 1,
            mtime = 1,
        )
        val encoded = SftpFileAttributes.encode(attrs)
        // flags(4) + size(8) + uid+gid(8) + permissions(4) + atime+mtime(8) = 32
        assertEquals(32, encoded.size)
    }
}
