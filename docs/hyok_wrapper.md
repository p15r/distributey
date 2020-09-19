# HYOK Wrapper
1. 💾 Copy certificate for key wrapping to `HYOK-Wrapper/config/backend/jwe-kid-salesforce-serviceX.crt`.
2. 💾 Copy TLS cert & key for reverse proxy:
   1. Copy key to: `HYOK-Wrapper/docker/certs/nginx.key`
   2. Copy cert to: `HYOK-Wrapper/docker/certs/nginx.crt`
3. 💾 Save pub key in PEM format from Salesforce to verify JWT tokens in `HYOK-Wrapper/config/auth/` and store its path in the key map `jwt_validation_certs`.
4. ✏️ If you plan to run `HYOK Wrapper` in prodction, go to `docker-compose.yaml` and comment configuration as documented. The default configuration runs HYOK Wrapper for development purposes, which will deploy Hashicorp Vault using its in-memory database.
5. 🛠️ Build docker images: `./00-build.sh`
6. 🚀 Run service: `./01-start.sh`
7. ✏️ Configure service: `HYOK-Wrapper/config/config.json`
8. 🔄 (Re-) load config: `./02-load-config.sh`

To stop or uninstall HYOK Wrapper:
- 🛑 Stop service: `./03-stop.sh`
- 🗑️ Remove service: `./04-remove.sh`
