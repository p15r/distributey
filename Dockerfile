FROM alpine:3.12 AS build-image

# Sets utf-8 encoding for Python et al
ENV LANG=C.UTF-8
# Turns off writing .pyc files; needless in build-image
ENV PYTHONDONTWRITEBYTECODE=1
# Seems to speed things up
ENV PYTHONUNBUFFERED=1

# Activate virtualenv
ENV PATH="/opt/venv/bin:$PATH"

# pyjwt[crypto] requires: python3-dev libffi-dev openssl-dev
# python3>=3.8: for walrus operator support
RUN apk add --no-cache python3>=3.8 python3-dev libffi-dev openssl-dev py3-pip build-base

RUN python3 -m venv /opt/venv
COPY requirements.txt /root/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /root/requirements.txt

FROM alpine:3.12

LABEL maintainer="pat@p15r.net"

ARG UNAME=hyok
ARG UID=1337
ARG GNAME=hyok
ARG GID=1337
ARG ROOT=/opt/hyok-wrapper

ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Activate virtualenv
ENV PATH="/opt/venv/bin:$PATH"

RUN addgroup -g ${GID} -S ${GNAME} && adduser -u ${UID} -G ${GNAME} -S -H ${UNAME}

COPY --from=build-image /opt/venv /opt/venv
RUN apk add --no-cache python3>=3.8

COPY --chown=${UNAME}:${GNAME} hyok-wrapper ${ROOT}
COPY --chown=${UNAME}:${GNAME} docker/entrypoint.sh ${ROOT}/entrypoint.sh

EXPOSE 5000

USER ${UID}

WORKDIR /opt/hyok-wrapper
CMD ["/opt/hyok-wrapper/entrypoint.sh"]
