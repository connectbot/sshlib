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
    echo "KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config && \
    echo "HostKeyAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config && \
    echo "Ciphers +aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc" >> /etc/ssh/sshd_config && \
    echo "MACs +hmac-sha2-256,hmac-sha2-512" >> /etc/ssh/sshd_config && \
    echo "KbdInteractiveAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "UsePAM yes" >> /etc/ssh/sshd_config

# Configure PAM for sshd
RUN mkdir -p /etc/pam.d && \
    echo "auth       required     pam_unix.so" > /etc/pam.d/sshd && \
    echo "account    required     pam_unix.so" >> /etc/pam.d/sshd && \
    echo "password   required     pam_unix.so" >> /etc/pam.d/sshd && \
    echo "session    required     pam_unix.so" >> /etc/pam.d/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
