# HYOK Wrapper

If you install `HYOK Wrapper` in an environment that has no internet access, follow instructions in [Offline Environment](#offline-environment) first.

The following actions are required to run `HYOK-Wrapper`:
-  If you plan to run `HYOK Wrapper` in prodction, go to `docker-compose.yaml` and comment configuration as documented with in-line comments. The default configuration runs HYOK Wrapper for development purposes, which will deploy Hashicorp Vault using its in-memory database.
- Build `HYOK Wrapper`: `./00-build.sh` & follow instructions
- Run service: `./01-start.sh`
- Configure service: `HYOK-Wrapper/config/config.json`
   - Check example config: `HYOK-Wrapper/dev/example-config.json`
- (Re-) load config: `./02-load-config.sh`

To stop or uninstall HYOK Wrapper:
- Stop service: `./03-stop.sh`
- Remove service: `./04-remove.sh`

## Offline Environment

Create terraform provider mirror zip archive:
- `mkdir ./tmpdir && cd ./tmpdir/`
- `cp HYOK-Wrapper/docker/terraform/main.tf .`
- `terraform providers mirror tf-cache`
- `zip -r tf-cache.zip tf-cache/`
- Upload `tf-cache.zip` to mirror (for example, a webserver) & set the variable `tf_provider_url_mirror_zip` accordingly in `01-start.sh`
