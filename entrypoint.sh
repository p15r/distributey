#!/usr/bin/env sh

# TODO: make nice system service:
# https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-18-04
gunicorn --workers 3 --bind 127.0.0.1:5000 --access-logfile - --error-logfile - wsgi:app &

/usr/sbin/nginx -g 'pid /tmp/nginx.pid; daemon off;'
