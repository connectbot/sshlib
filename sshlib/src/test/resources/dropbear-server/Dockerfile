FROM alpine:edge
ENV USERNAME testuser
ENV PASSWORD testtest123
ENV OPTIONS ""

# Add our test user with no login shell.
RUN adduser -g 'Test User' -s /bin/ash -D $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd

COPY run.sh /run.sh
RUN chmod +x run.sh

EXPOSE 22
CMD ["/run.sh"]

COPY *.pub /
RUN mkdir /home/$USERNAME/.ssh && \
    chmod 0700 /home/$USERNAME/.ssh && \
    cat /*.pub > /home/$USERNAME/.ssh/authorized_keys && \
    chmod 0600 /home/$USERNAME/.ssh/authorized_keys && \
    chown -R $USERNAME /home/$USERNAME/.ssh && \
    rm -f /*.pub

# Install OpenSSH server to test against
# TODO[kenny]: Add consistent host keys?
RUN apk add --no-cache dropbear && \
    mkdir -p /etc/dropbear && \
    dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key && \
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
