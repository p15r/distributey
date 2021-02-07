# Prerequisites 📚
- `openssl`
- `docker` (tested with `19.03.13`)
  - add user to group `docker`(`sudo usermod -a -G docker USER`) or run scripts with `sudo`
- `docker-compose` (tested with `v3.7`)
- `terrafrom` binary accessible via `$PATH` (tested with `v0.13.4`)
- TLS certificate & key for reverse proxy.
  - `Nginx` is used as reverse proxy. Create a certificate that matches your desired URL (`CN`) of `distributey`. Most key consumers, such as Salesforce, require a valid certificate, signed by an official root CA. Store the certificate as `distributey/docker/certs/nginx.crt` and the key as `distributey/docker/certs/nginx.key`.
  - Use the following command to generate self-signed certificates (for development purposes only): `openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout distributey/docker/certs/nginx.key -out distributey/docker/certs/nginx.crt -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName"`
- `distributey` comes with some helper tools that can be found under `dev/`. To use them, the python dependencies must be satisfied
  - create a virtual environment: `python3 -m venv /path/to/venv`
  - activate virtual environment: `source /path/to/venv/bin/activate`
  - install dependencies: `python3 -m pip install -r requirements.txt`
  - type `deactivate` to exit the virtual environment

## Security

This section is optional. If security is especially important, enable following protection measures on infrastructure level:
- Ensure network traffic is restricted between containers.
- Enable user namespace support
  - https://docs.docker.com/engine/security/userns-remap/
  - https://dreamlab.net/en/blog/post/user-namespace-remapping-an-advanced-feature-to-protect-your-docker-environments/
- Ensure cgroup usage has been confirmed:
  - Get container id: `docker inspect distributey | jq '.[0].Id'`
  - List cgroup usage of container: `lscgroup | grep <id>`
    - example output:
    ```bash
    perf_event:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    pids:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    cpu,cpuacct:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    memory:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    freezer:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    net_cls,net_prio:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    blkio:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    hugetlb:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    cpuset:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    devices:/docker/edad520db3ed1227afeb88ae2c28d78acd93f294d062b6648976c18afe564d0b
    ```
- Enable docker live restore: https://docs.docker.com/config/containers/live-restore/
- Ensure that authorization for Docker client commands is enabled (authorization plugin required)
- Once audited, enable Docker content trust: https://docs.docker.com/engine/security/trust/
- By default, the default docker seccomp profile [link](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) is loaded. A more restrictive seccomp profile could be created.
