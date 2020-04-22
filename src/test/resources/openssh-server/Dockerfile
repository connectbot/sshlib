FROM alpine:edge
ENV USERNAME testuser
ENV PASSWORD testtest123
ENV OPTIONS ""

# Add our test user with no login shell.
RUN adduser -g 'Test User' -s /sbin/nologin -D $USERNAME && \
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
RUN apk add --no-cache openssh-server openssh-keygen && \
    ssh-keygen -A
