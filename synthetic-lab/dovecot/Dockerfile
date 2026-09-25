# Dovecot Dockerfile for SecureMailScope Synthetic Lab
FROM alpine:3.19

RUN apk add --no-cache dovecot dovecot-pop3d openssl ca-certificates && \
    mkdir -p /certs /var/mail /var/run/dovecot

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 143 110

ENTRYPOINT ["/entrypoint.sh"]
