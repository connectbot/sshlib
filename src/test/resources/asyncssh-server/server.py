# To run this program, the file ``ssh_host_key`` must exist with an SSH
# private key in it to use as a server host key. An SSH host certificate
# can optionally be provided in the file ``ssh_host_key-cert.pub``.

import asyncio, asyncssh, sys, logging

passwords = {
             'user123': 'secretpw'
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
        self._conn = conn;

    def connection_lost(self, exc):
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
        else:
            print('SSH connection closed.')

    def begin_auth(self, username):
        # If the user's password is the empty string, no auth is required
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
                                          process_factory=handle_client)
    return server

async def main():
    print("SETTING LOGGER")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

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
