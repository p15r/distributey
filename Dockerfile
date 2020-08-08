FROM alpine:3.12

# TODO: https, dedicated user, nginx as side-car

# install deps first to benefit from docker caching
RUN apk add python3 py3-pip build-base nginx

RUN mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf_

COPY hyok-wrapper /opt/hyok-wrapper

RUN python3 -m pip install -r /opt/hyok-wrapper/requirements.txt

COPY entrypoint.sh /opt/hyok-wrapper/entrypoint.sh

RUN ln -s /opt/hyok-wrapper/nginx.conf /etc/nginx/conf.d/hyok-wrapper.conf
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
  && ln -sf /dev/stderr /var/log/nginx/error.log

EXPOSE 80

WORKDIR /opt/hyok-wrapper

CMD ["/opt/hyok-wrapper/entrypoint.sh"]
