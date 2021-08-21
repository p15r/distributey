FROM alpine:latest AS build-image

# Sets utf-8 encoding for Python et al
ENV LANG=C.UTF-8
# Turns off writing .pyc files; needless in build-image
ENV PYTHONDONTWRITEBYTECODE=1
# Seems to speed things up
ENV PYTHONUNBUFFERED=1

# Activate virtualenv
ENV PATH="/opt/venv/bin:$PATH"

# Disable rust build for py req "cryptography"
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1

RUN apk update && apk update && apk add curl

# pyjwt[crypto] requires: python3-dev libffi-dev openssl-dev
# python3>=3.8: for walrus operator support
RUN apk add --no-cache python3>=3.8 python3-dev libffi-dev openssl-dev py3-pip build-base

RUN python3 -m venv /opt/venv
RUN python3 -m pip install --upgrade pip
COPY requirements.txt /root/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /root/requirements.txt

FROM alpine:latest

LABEL maintainer="pat@p15r.net"

ARG UNAME=distributey
ARG UID=1337
ARG GNAME=distributey
ARG GID=1337
ARG ROOT=/opt/distributey

ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

ENV DY_CFG_PATH=/opt/distributey/config/config.json

RUN apk update && apk update && apk add curl

# Activate virtualenv
ENV PATH="/opt/venv/bin:$PATH"

RUN addgroup -g ${GID} -S ${GNAME} && adduser -u ${UID} -G ${GNAME} -S -H ${UNAME}

COPY --from=build-image /opt/venv /opt/venv
RUN apk add --no-cache python3>=3.8

# copy distributey src
COPY --chown=0:0 distributey ${ROOT}
COPY --chown=0:0 docker/entrypoint.sh ${ROOT}/entrypoint.sh

# set distributey src fs permission
RUN find /opt/distributey/ -type d -exec chmod o+rx {} \;
RUN find /opt/distributey/ -type f -exec chmod o+r {} \;
RUN chmod o+rx ${ROOT}/entrypoint.sh

EXPOSE 5000

USER ${UID}

WORKDIR /opt/distributey
CMD ["/opt/distributey/entrypoint.sh"]
