# https://github.com/hashicorp/vault/blob/master/scripts/docker/Dockerfile
FROM hashicorp/vault

RUN apk add shadow

RUN usermod -u 101 vault

# add vault owned config and certificate paths
RUN mkdir -p /vault/config
RUN mkdir -p /vault/certs
RUN chown -R vault: /vault

# init server cert file
RUN touch /vault/certs/serverissue.json