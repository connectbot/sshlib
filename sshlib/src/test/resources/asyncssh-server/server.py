# To run this program, the file ``ssh_host_key`` must exist with an SSH
# private key in it to use as a server host key. An SSH host certificate
# can optionally be provided in the file ``ssh_host_key-cert.pub``.

import asyncio, asyncssh, crypt, sys, time

passwords = {
             'user123': 'qV2iEadIGV2rw'   # password of 'secretpw'
            }

def handle_client(process):
    process.stdout.write('success\n')
    time.sleep(10)
    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        print('SSH connection received from %s.' %
                  conn.get_extra_info('peername')[0])

    def connection_lost(self, exc):
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
        else:
            print('SSH connection closed.')

    def begin_auth(self, username):
        # If the user's password is the empty string, no auth is required
        return passwords.get(username) != ''

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        pw = passwords.get(username, '*')
        return crypt.crypt(password, pw) == pw

async def start_server():
    print("READY")
    await asyncssh.create_server(MySSHServer, '', 8022,
                                 server_host_keys=[
                                     '/etc/ssh/ssh_host_ecdsa_key',
                                     '/etc/ssh/ssh_host_rsa_key',
                                 ],
                                 process_factory=handle_client)

print("STARTING UP")
loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

# Only run the loop once for testing
#loop.call_soon(loop.stop)
loop.run_forever()