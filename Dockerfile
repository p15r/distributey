FROM alpine:3.12

LABEL maintainer="pat@p15r.net"

ARG UNAME=hyok
ARG UID=1337
ARG GNAME=hyok
ARG GID=1337
ARG ROOT=/opt/hyok-wrapper

RUN addgroup -g ${GID} -S ${GNAME} && adduser -u ${UID} -G ${GNAME} -S -H ${UNAME}

# install deps first to benefit from docker caching
# pyjwt[crypto] requires: python3-dev libffi-dev openssl-dev
RUN apk add python3 python3-dev libffi-dev openssl-dev py3-pip build-base
COPY requirements.txt /root/requirements.txt
RUN python3 -m pip install -r /root/requirements.txt

COPY --chown=${UNAME}:${GNAME} hyok-wrapper ${ROOT}
COPY --chown=${UNAME}:${GNAME} docker/entrypoint.sh ${ROOT}/entrypoint.sh

EXPOSE 5000

USER ${UID}

WORKDIR /opt/hyok-wrapper
CMD ["/opt/hyok-wrapper/entrypoint.sh"]
