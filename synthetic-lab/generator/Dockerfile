# Generator Dockerfile for SecureMailScope Synthetic Lab
FROM alpine:3.19

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-cryptography \
    tcpdump \
    tshark \
    openssl \
    ca-certificates

WORKDIR /app

COPY generate_certs.py /app/generate_certs.py
COPY generate_scenarios.py /app/generate_scenarios.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
