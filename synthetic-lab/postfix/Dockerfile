# Postfix Dockerfile for SecureMailScope Synthetic Lab
FROM alpine:3.19

RUN apk add --no-cache postfix openssl ca-certificates && \
    mkdir -p /certs /var/log && \
    touch /var/log/postfix.log

COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 2525 2526 2527 2528

ENTRYPOINT ["/entrypoint.sh"]
