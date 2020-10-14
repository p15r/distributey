# HYOK Wrapper Installation

If you install `HYOK Wrapper` in an environment that has no internet access, follow the instructions for [Offline Environments](#offline-environment) first.

The following actions are required to configure & run `HYOK-Wrapper`:
-  If you plan to run `HYOK Wrapper` in production, edit `docker-compose.yaml` and comment configuration as documented with in-line comments. The default configuration runs `HYOK Wrapper` in development mode, which deploys Hashicorp Vault using its in-memory database.
- Build service: run `./00-build.sh` (`./00-build.sh -d` if you are developer)
- Run service: `./01-start.sh`
- Configure service: `config/config.json`
   - Check example config: `dev/example-config.json`
- (Re-) load config: `./02-load-config.sh`
- `HYOK Wrapper` is now operational
- For audit purposes, container logs are written to the host's logging infrastructure. `docker-compose.yaml` can be edited to forward logs to a remote logging infrastructure ([link](https://docs.docker.com/config/containers/logging/syslog/)).

To stop or uninstall `HYOK Wrapper`:
- Stop service: `./03-stop.sh`
- Remove service: `./04-remove.sh`

## Offline Environments

In order for `HYOK Wrapper` to operate in offline environments, make sure to configure private container registries for all container images in `docker-compose.yaml`. Further, `HYOK Wrapper` uses `terraform` which requires provider plugins. Make the required provider plugins available in an offline environment by following these instructions:

- `mkdir ./tmpdir && cd ./tmpdir/`
- `cp HYOK-Wrapper/docker/terraform/main.tf .`
- `terraform providers mirror tf-cache`
- `zip -r tf-cache.zip tf-cache/`
- Upload `tf-cache.zip` to mirror (for example, a webserver) and remember its URL
- In `01-start.sh`, configure the variable `tf_provider_url_mirror_zip` accordingly
