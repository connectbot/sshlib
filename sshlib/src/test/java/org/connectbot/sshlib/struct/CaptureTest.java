/*
 * Copyright 2019 Kenny Root
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

package org.connectbot.sshlib.struct;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CaptureTest {
    @Test
    public void serverToClient() throws Exception {
        InputStream is = CaptureTest.class.getResourceAsStream("server-to-client.cap");
        DataInputStream dis = new DataInputStream(is);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteBufferKaitaiStream bb = new ByteBufferKaitaiStream(bytes);
        IdBanner banner = new IdBanner(bb);
        banner._read();
        System.out.println("Banner: " + banner.protoVersion());

        int seqNum = 1;
        while (printPlain(bb) != SshEnums.MessageType.SSH_MSG_NEWKEYS) { seqNum++; }
        while (!bb.isEof()) {
            printEnc(bb, seqNum++);
        }
    }

    private SshEnums.MessageType printPlain(ByteBufferKaitaiStream bb) {
        UnencryptedPacket msg = new UnencryptedPacket(bb);
        msg._read();
        System.out.print("unencrypted msg: ");
        switch (msg.payload().messageType()) {
            case SSH_MSG_KEXINIT:
                System.out.println(msg.payload().messageType());
                SshMsgKexinit init = (SshMsgKexinit) msg.payload().body();
                System.out.print("serverHostKeyAlgorithms: ");
                System.out.println(init.serverHostKeyAlgorithms());
                break;

            case SSH_MSG_KEX_METHOD_SPECIFIC_30:
            case SSH_MSG_KEX_METHOD_SPECIFIC_31:
            case SSH_MSG_KEX_METHOD_SPECIFIC_32:
            case SSH_MSG_KEX_METHOD_SPECIFIC_33:
            case SSH_MSG_KEX_METHOD_SPECIFIC_34:
            case SSH_MSG_KEX_METHOD_SPECIFIC_35:
            case SSH_MSG_KEX_METHOD_SPECIFIC_36:
            case SSH_MSG_KEX_METHOD_SPECIFIC_37:
            case SSH_MSG_KEX_METHOD_SPECIFIC_38:
            case SSH_MSG_KEX_METHOD_SPECIFIC_39:
            case SSH_MSG_KEX_METHOD_SPECIFIC_40:
            case SSH_MSG_KEX_METHOD_SPECIFIC_41:
            case SSH_MSG_KEX_METHOD_SPECIFIC_42:
            case SSH_MSG_KEX_METHOD_SPECIFIC_43:
            case SSH_MSG_KEX_METHOD_SPECIFIC_44:
            case SSH_MSG_KEX_METHOD_SPECIFIC_45:
            case SSH_MSG_KEX_METHOD_SPECIFIC_46:
            case SSH_MSG_KEX_METHOD_SPECIFIC_47:
            case SSH_MSG_KEX_METHOD_SPECIFIC_48:
            case SSH_MSG_KEX_METHOD_SPECIFIC_49:
                kexdhPrint(msg);
                break;
            default:
                System.out.println(msg.payload().messageType());
                break;
        }
        return msg.payload().messageType();
    }

    private void kexdhPrint(UnencryptedPacket msg) {
        KexdhPayload kexdhPayload = new KexdhPayload(
                new ByteBufferKaitaiStream(msg._raw_payload()), msg);
        kexdhPayload._read();
        System.out.println(kexdhPayload.messageType());
        switch (kexdhPayload.messageType()) {
            case SSH_MSG_KEXDH_INIT:
                System.out.print("e: ");
                SshMsgKexdhInit dhinit = (SshMsgKexdhInit) kexdhPayload.body();
                System.out.println(new BigInteger(1, dhinit.e().body()).toString(16));
                break;
            case SSH_MSG_KEXDH_REPLY:
                SshMsgKexdhReply dhreply = (SshMsgKexdhReply) kexdhPayload.body();
                System.out.print("server_key: ");
                System.out.println(new String(dhreply.serverKey().data()));
                System.out.print("f: ");
                System.out.println(new BigInteger(1, dhreply.f().body()).toString(16));
                break;
        }
    }

    private static final String MAC_ALGO = "HmacSHA256";

    /*
     * hash
     * 0000: 9e f5 c8 c3 7c 33 75 d9 46 65 53 a3 e9 44 16 22  ....|3u.FeS..D."
     * 0016: 14 b8 1b b8 0a 1e 39 32 b2 89 96 57 14 13 7b c1  ......92...W..{.
     * key 'A'== key (initial IV client-to-server)
     * 0000: 76 20 6e 50 ff 17 43 9c 50 5d 2b 1a 96 52 42 8c  v nP..C.P]+..RB.
     * 0016: 55 af d8 31 0f 86 52 75 d5 fc 9f 70 ab d2 ce 45  U..1..Ru...p...E
     * key 'B'== key (initial IV server-to-client)
     * 0000: 4a d0 83 35 66 c6 2e da 2b f4 5b 44 79 da cb c2  J..5f...+.[Dy...
     * 0016: 3f b7 ac 4a 2d 5d b8 73 55 fa 81 1b 7b 46 fc c4  ?..J-].sU...{F..
     * key 'C'== key (encryption key client-to-server)
     * 0000: 9d 53 e1 10 b6 62 41 2c 06 a5 b7 6d ba 98 b1 23  .S...bA,...m...#
     * 0016: 7d 37 74 4e 15 9c f7 fd 59 e8 4e 12 aa aa f0 40  }7tN....Y.N....@
     * key 'D'== key (encryption key server-to-client)
     * 0000: f0 6f c5 74 24 38 6c 6c 53 53 a0 2b a2 c0 45 82  .o.t$8llSS.+..E.
     * 0016: de 61 50 f2 41 b1 f8 4f 97 a5 d2 22 e4 d6 96 eb  .aP.A..O..."....
     * key 'E'== key (mac key client-to-server)
     * 0000: 26 4f 54 6a c7 64 f9 96 2c 62 08 c0 6d ce 50 93  &OTj.d..,b..m.P.
     * 0016: 26 ae d9 31 7e 8c 2b b6 11 8c b1 f9 2b 32 14 24  &..1~.+.....+2.$
     * key 'F'== key (mac key server-to-client)
     * 0000: e0 03 a2 02 7d 34 06 f0 6c 9f e4 45 3d f0 e1 e0  ....}4..l..E=...
     * 0016: b6 fb 21 0d 6d a6 fc 5a e4 86 61 ac 00 33 c4 ce  ..!.m..Z..a..3..
     */
    private static final byte[] initialIv_StoC = new byte[] {
(byte) 0x4a, (byte) 0xd0, (byte) 0x83, (byte) 0x35, (byte) 0x66, (byte) 0xc6, (byte) 0x2e, (byte) 0xda, (byte) 0x2b, (byte) 0xf4, (byte) 0x5b, (byte) 0x44, (byte) 0x79, (byte) 0xda, (byte) 0xcb, (byte) 0xc2,
/* (byte) 0x3f, (byte) 0xb7, (byte) 0xac, (byte) 0x4a, (byte) 0x2d, (byte) 0x5d, (byte) 0xb8, (byte) 0x73, (byte) 0x55, (byte) 0xfa, (byte) 0x81, (byte) 0x1b, (byte) 0x7b, (byte) 0x46, (byte) 0xfc, (byte) 0xc4, */
    };
    private static final byte[] cipherKey_StoC = new byte[] {
(byte) 0xf0, (byte) 0x6f, (byte) 0xc5, (byte) 0x74, (byte) 0x24, (byte) 0x38, (byte) 0x6c, (byte) 0x6c, (byte) 0x53, (byte) 0x53, (byte) 0xa0, (byte) 0x2b, (byte) 0xa2, (byte) 0xc0, (byte) 0x45, (byte) 0x82,
/*(byte) 0xde, (byte) 0x61, (byte) 0x50, (byte) 0xf2, (byte) 0x41, (byte) 0xb1, (byte) 0xf8, (byte) 0x4f, (byte) 0x97, (byte) 0xa5, (byte) 0xd2, (byte) 0x22, (byte) 0xe4, (byte) 0xd6, (byte) 0x96, (byte) 0xeb,*/
    };
    private static final SecretKeySpec CIPHER_KEY = new SecretKeySpec(cipherKey_StoC, "AES");

    private static final byte[] hmacKey_StoC = new byte[] {
        (byte) 0xe0, (byte) 0x03, (byte) 0xa2, (byte) 0x02, (byte) 0x7d, (byte) 0x34, (byte) 0x06, (byte) 0xf0, (byte) 0x6c, (byte) 0x9f, (byte) 0xe4, (byte) 0x45, (byte) 0x3d, (byte) 0xf0, (byte) 0xe1, (byte) 0xe0,
        (byte) 0xb6, (byte) 0xfb, (byte) 0x21, (byte) 0x0d, (byte) 0x6d, (byte) 0xa6, (byte) 0xfc, (byte) 0x5a, (byte) 0xe4, (byte) 0x86, (byte) 0x61, (byte) 0xac, (byte) 0x00, (byte) 0x33, (byte) 0xc4, (byte) 0xce,
    };
    private static final SecretKeySpec MAC_KEY = new SecretKeySpec(hmacKey_StoC, MAC_ALGO);

    private byte[] iv = initialIv_StoC.clone();

    private byte[] toByteArray(KaitaiStruct.ReadWrite struct) throws Exception {
	struct._check();
        KaitaiStream io = new ByteBufferKaitaiStream(1024 * 16);
        struct._write(io);
        long size = io.pos();
        io.seek(0);
        return io.readBytes(size);
    }

    private void printEnc(ByteBufferKaitaiStream bb, int seqNum) throws Exception {
        EncryptedPacket msg = new EncryptedPacket(bb, 32);
        msg._read();
        System.out.print("encrypted size: ");
        System.out.println(msg.lenEncryptedPayload());
        Mac mac = Mac.getInstance(MAC_ALGO);
        mac.init(MAC_KEY);

        EtmMac macInput = new EtmMac();
        macInput.setLenEncryptedPacket(msg.lenEncryptedPayload());
        macInput.setEncryptedPacket(msg.encryptedPayload());
        macInput.setSequenceNumber(seqNum);
        byte[] tag = mac.doFinal(toByteArray(macInput));

        System.out.println("calculated tag: " + new BigInteger(1, tag).toString(16));
        System.out.println("    actual tag: " + new BigInteger(1, msg.mac()).toString(16));

        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        c.init(Cipher.DECRYPT_MODE, CIPHER_KEY, ivSpec);
        byte[] decryptedBytes = c.doFinal(msg.encryptedPayload());

        System.out.println("decrypted: " + new BigInteger(1, decryptedBytes).toString(16));

        incrementIv(iv, decryptedBytes.length / c.getBlockSize());

        ByteBufferKaitaiStream dbytes = new ByteBufferKaitaiStream(decryptedBytes);
        EncryptedPacket.DecryptedPacket dmsg = new EncryptedPacket.DecryptedPacket(dbytes, msg);
        dmsg._read();
        System.out.print("decrypted msg: ");
        System.out.println(dmsg.payload().messageType());
        switch (dmsg.payload().messageType()) {
            case SSH_MSG_CHANNEL_DATA:
                SshMsgChannelData data = (SshMsgChannelData) dmsg.payload().body();
                System.out.print("channel: ");
                System.out.println(data.recipientChannel());
                System.out.print("data: ");
                System.out.println(new String(data.data().data()));
                break;
        }
    }

    private void incrementIv(byte[] iv, int numBlocks) {
        int carry = numBlocks;
        for (int i = iv.length - 1; i > 0; i--) {
            int sum = (iv[i] & 0xFF) + carry;
            iv[i] = (byte) sum;
            carry = sum >> 8;
            if (carry == 0)
                break;
        }
    }
}
