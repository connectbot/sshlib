FROM python:3-alpine3.12

EXPOSE 8022
ENV PYTHONUNBUFFERED=0
ENTRYPOINT ["python", "-u", "server.py"]

COPY requirements.txt .
RUN apk add --no-cache --virtual build-deps gcc python3-dev musl-dev libffi-dev openssl-dev openssh-keygen libsodium-dev rust cargo && \
    apk add --no-cache openssl && \
    mkdir /etc/ssh && \
    ssh-keygen -A && \
    pip install --upgrade pip && \
    pip install -r requirements.txt && \
    apk del build-deps

COPY server.py .
COPY *.pub /
RUN cat /*.pub > /authorized_keys && rm -f /*.pub
