FROM python:3.12-slim-bookworm AS builder
RUN apt-get update && \
    apt-get install -y gcc openssh-server && \
    apt-get clean
COPY requirements.txt /app/requirements.txt
WORKDIR app
RUN pip install --user -r requirements.txt
RUN mkdir -p /etc/ssh && ssh-keygen -A
COPY . /app

FROM python:3.12-slim-bookworm AS app
COPY --from=builder /etc/ssh /etc/ssh
COPY --from=builder /root/.local /root/.local
COPY --from=builder /app/server.py /app/server.py
WORKDIR app
EXPOSE 8022
ENV PYTHONUNBUFFERED=0
ENTRYPOINT ["python", "-u", "server.py"]
COPY *.pub /app/
RUN cat /app/*.pub > /app/authorized_keys && rm -f /app/*.pub
