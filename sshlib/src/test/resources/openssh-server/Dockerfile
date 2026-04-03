FROM alpine:edge

ENV USERNAME testuser
ENV PASSWORD testpass

# Install build dependencies and compile OpenSSH from source
RUN apk update && apk add --no-cache \
    build-base \
    autoconf \
    make \
    gcc \
    musl-dev \
    zlib-dev \
    openssl-dev \
    libedit-dev \
    linux-pam-dev \
    linux-headers && \
    \
    # Download and extract OpenSSH
    SSH_VERSION="9.9p2" && \
    wget "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${SSH_VERSION}.tar.gz" -O "/tmp/openssh-${SSH_VERSION}.tar.gz" && \
    tar -xzf "/tmp/openssh-${SSH_VERSION}.tar.gz" -C /tmp && \
    cd "/tmp/openssh-${SSH_VERSION}" && \
    \
    # Configure with debug flags and install
    CFLAGS="-DDEBUG_KEX -DDEBUG_KEXECDH -DDEBUG_KEXDH -DDEBUG_PK" ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/empty --with-pam && \
    make && \
    make install && \
    \
    # Clean up
    cd / && \
    rm -rf "/tmp/openssh-${SSH_VERSION}.tar.gz" "/tmp/openssh-${SSH_VERSION}" && \
    apk del build-base autoconf make gcc musl-dev zlib-dev openssl-dev libedit-dev linux-pam-dev linux-headers && \
    apk add --no-cache linux-pam

# Create test user
RUN adduser -g 'Test User' -s /bin/sh -D $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd

# Configure SSH
RUN mkdir -p /run/openssh && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1" >> /etc/ssh/sshd_config && \
    echo "HostKeyAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config && \
    echo "Ciphers +aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc" >> /etc/ssh/sshd_config && \
    echo "MACs +hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com" >> /etc/ssh/sshd_config && \
    echo "KbdInteractiveAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "UsePAM yes" >> /etc/ssh/sshd_config && \
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config && \
    echo "GatewayPorts yes" >> /etc/ssh/sshd_config && \
    echo "MaxAuthTries 20" >> /etc/ssh/sshd_config

# Set up public key authentication for test user
COPY test_ed25519.pub /tmp/test_ed25519.pub
RUN mkdir -p /home/$USERNAME/.ssh && \
    cat /tmp/test_ed25519.pub >> /home/$USERNAME/.ssh/authorized_keys && \
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh && \
    chmod 700 /home/$USERNAME/.ssh && \
    chmod 600 /home/$USERNAME/.ssh/authorized_keys && \
    rm /tmp/test_ed25519.pub

# Configure PAM for sshd
RUN mkdir -p /etc/pam.d && \
    echo "auth       required     pam_unix.so" > /etc/pam.d/sshd && \
    echo "account    required     pam_unix.so" >> /etc/pam.d/sshd && \
    echo "password   required     pam_unix.so" >> /etc/pam.d/sshd && \
    echo "session    optional     pam_unix.so" >> /etc/pam.d/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
