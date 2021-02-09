# distributey Installation

If you install `distributey` in an environment that has no internet access, follow the instructions for [Offline Environments](#offline-environment) first.

The following actions are required to configure & run `distributey`:
- If you plan to run `distributey` in production, edit `docker-compose.yaml` and comment configuration as documented with in-line comments. The default configuration runs `distributey` in development mode, which deploys Hashicorp Vault using its in-memory database.
- Build service: run `./00-build.sh` (`./00-build.sh -d` if you are developer)
- Configure service: `config/config.json`
   - Check example config: `dev/example-config.json`
- Set config files permissions: `./02-fix-cfg-perms.sh`
- Run service: `./01-start.sh`
- `distributey` is now operational
- For audit purposes, container logs are written to the host's logging infrastructure. However, `docker-compose.yaml` can be edited to forward logs to a remote logging service as well ([link](https://docs.docker.com/config/containers/logging/syslog/)).

To stop or remove `distributey`:
- Stop service: `./03-stop.sh`
- Remove service: `./04-remove.sh`

## Offline Environments

In order for `distributey` to operate in offline environments, make sure to configure private container registries for all container images in `docker-compose.yaml`. Further, `distributey` relies on `terraform` which requires provider plugins. Make them available in an offline environment by following these instructions:

- `mkdir ./tmpdir && cd ./tmpdir/`
- `cp distributey/docker/terraform/main.tf .`
- `terraform providers mirror -platform=linux_amd64 tf-cache`
- `zip -r tf-cache.zip tf-cache/`
- Upload `tf-cache.zip` to mirror (for example, a webserver) and remember its URL
- In `01-start.sh`, configure the variable `tf_provider_url_mirror_zip` accordingly
