import asyncio
import asyncssh
import sys

passwords = {
             'testuser': 'testpass'
            }

async def handle_client(process):
    process.stdout.write('success\n')
    await asyncio.sleep(10)
    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def __init__(self):
        self._conn = None

    def connection_made(self, conn):
        print('SSH connection received from %s.' %
                  conn.get_extra_info('peername')[0])
        self._conn = conn

    def connection_lost(self, exc):
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
        else:
            print('SSH connection closed.')

    def begin_auth(self, username):
        self._conn.set_authorized_keys('authorized_keys')
        return passwords.get(username) != ''

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        pw = passwords.get(username, '*')
        return password == pw

    def public_key_auth_supported(self):
        return True


async def start_server():
    asyncssh.set_log_level('DEBUG')
    asyncssh.set_debug_level(2)
    server = await asyncssh.create_server(MySSHServer, '', 8022,
                                          server_host_keys=[
                                              '/app/etc/ssh/ssh_host_ecdsa_key',
                                              '/app/etc/ssh/ssh_host_rsa_key',
                                          ],
                                          kex_algs=[
                                              'curve25519-sha256',
                                              'curve25519-sha256@libssh.org',
                                              'ecdh-sha2-nistp256',
                                              'ecdh-sha2-nistp384',
                                              'ecdh-sha2-nistp521',
                                              'diffie-hellman-group-exchange-sha256',
                                              'diffie-hellman-group-exchange-sha1',
                                              'diffie-hellman-group18-sha512',
                                              'diffie-hellman-group16-sha512',
                                              'diffie-hellman-group14-sha256',
                                              'diffie-hellman-group14-sha1',
                                              'diffie-hellman-group1-sha1',
                                          ],
                                          encryption_algs=[
                                              'chacha20-poly1305@openssh.com',
                                              'aes256-gcm@openssh.com',
                                              'aes128-gcm@openssh.com',
                                              'aes256-ctr',
                                              'aes128-ctr',
                                              'aes256-cbc',
                                              'aes128-cbc',
                                              '3des-cbc',
                                          ],
                                          mac_algs=[
                                              'hmac-sha2-256-etm@openssh.com',
                                              'hmac-sha2-512-etm@openssh.com',
                                              'hmac-sha1-etm@openssh.com',
                                              'hmac-sha2-256',
                                              'hmac-sha2-512',
                                              'hmac-sha1',
                                          ],
                                          process_factory=handle_client)
    return server

async def main():
    print("STARTING UP")

    try:
        server = await start_server()
    except (OSError, asyncssh.Error) as exc:
        sys.exit('Error starting server: ' + str(exc))

    print("LISTENER READY")

    async with server:
        await server.wait_closed()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutting down...")
