FROM alpine:3.12

LABEL maintainer="pat@p15r.net"

ARG UNAME=hyok
ARG UID=1337
ARG GNAME=hyok
ARG GID=1337
ARG ROOT=/opt/hyok-wrapper

# install deps first to benefit from docker caching
RUN apk add python3 py3-pip build-base
COPY requirements.txt /root/requirements.txt
RUN python3 -m pip install -r /root/requirements.txt

COPY --chown=nobody:nobody hyok-wrapper ${ROOT}
COPY --chown=nobody:nobody docker/entrypoint.sh ${ROOT}/entrypoint.sh

# "output" dir must be writable by gunicorn
RUN chown ${UID}:${GID} ${ROOT}/output
VOLUME ${ROOT}/output

EXPOSE 5000

RUN addgroup -g ${GID} -S ${GNAME} && adduser -u ${UID} -G ${GNAME} -S -H ${UNAME}
USER ${UID}

WORKDIR /opt/hyok-wrapper
CMD ["/opt/hyok-wrapper/entrypoint.sh"]
