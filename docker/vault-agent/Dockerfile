# https://github.com/hashicorp/vault/blob/master/scripts/docker/Dockerfile
FROM vault:1.5.3

RUN apk add shadow

# adjust the uid for the vault user to match the uid of the consumer (nginx):
# https://github.com/nginxinc/docker-nginx-unprivileged/blob/main/stable/alpine/Dockerfile#L131
RUN usermod -u 101 vault

# add vault owned config and certificate paths
RUN mkdir -p /vault/config
RUN mkdir -p /vault/certs
RUN chown -R vault: /vault

# init server cert file
RUN touch /vault/certs/serverissue.json
