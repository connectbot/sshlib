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
    linux-headers && \
    \
    # Download and extract OpenSSH
    SSH_VERSION="9.9p2" && \
    wget "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${SSH_VERSION}.tar.gz" -O "/tmp/openssh-${SSH_VERSION}.tar.gz" && \
    tar -xzf "/tmp/openssh-${SSH_VERSION}.tar.gz" -C /tmp && \
    cd "/tmp/openssh-${SSH_VERSION}" && \
    \
    # Configure with debug flags and install
    CFLAGS="-DDEBUG_KEX -DDEBUG_KEXECDH -DDEBUG_KEXDH -DDEBUG_PK" ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/empty && \
    make && \
    make install && \
    \
    # Clean up
    cd / && \
    rm -rf "/tmp/openssh-${SSH_VERSION}.tar.gz" "/tmp/openssh-${SSH_VERSION}" && \
    apk del build-base autoconf make gcc musl-dev zlib-dev openssl-dev libedit-dev linux-headers

# Create test user
RUN adduser -g 'Test User' -s /bin/sh -D $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd

# Configure SSH
RUN mkdir -p /run/openssh && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e", "-oKexAlgorithms=diffie-hellman-group14-sha256"]
