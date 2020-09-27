# Prerequisites 📚
- `docker` (19.03.13+)
  - add user to `docker` group: `sudo usermod -a -G docker USER`
- `docker-compose` (v3.7+)
- `terrafrom` binary accessible via `$PATH`
- TLS certificate & key for reverse proxy. `Nginx` is used as reverse proxy. Create a certificate that matches your desired URL (`CN`) of the HYOK Wrapper. Most key consumers, such as Salesforce, require a valid certificate, signed by an official root CA. Store the certificate as `HYOK-Wrapper/docker/certs/nginx.crt` and the key as `HYOK-Wrapper/docker/certs/nginx.key`.
  - Use the following command to generate self-signed certificates (for development purposes only): `openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout HYOK-Wrapper/docker/certs/nginx.key -out HYOK-Wrapper/docker/certs/nginx.crt -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName"`
