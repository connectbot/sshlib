FROM python:3-alpine

RUN apk add --no-cache --virtual build-deps gcc python3-dev musl-dev libffi-dev openssl-dev openssh-keygen && \
    apk add --no-cache openssl && \
    mkdir /etc/ssh && \
    ssh-keygen -A && \
    pip install asyncssh && \
    apk del build-deps

EXPOSE 8022
ENV PYTHONUNBUFFERED=0
ENTRYPOINT ["python", "-u", "server.py"]
COPY server.py server.py
