# HYOK Wrapper
1. Copy certificate for key wrapping to `HYOK-Wrapper/hyok-wrapper/key_consumer_cert.crt`.
2. Install TLS cert & key for reverse proxy:
   1. Copy key to: `HYOK-Wrapper/docker/certs/nginx.key`
   2. Copy cert to: `HYOK-Wrapper/docker/certs/nginx.crt`
3. Save pub key from Salesforce to verify JWT tokens in `config/` and store its path in the key map `JWT_VALIDATION_CERTS`.
4. If you plan to run `HYOK Wrapper` in developer mode, uncomment the following block in `docker-compose.yaml`:
    ```yaml
    vault:
      image: vault:1.5.0
      container_name: vault
      hostname: vault
      restart: always
      cap_add:
        - IPC_LOCK
      environment:
        - VAULT_DEV_ROOT_TOKEN_ID=root          # server config
        - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 # server config
        - VAULT_ADDR=http://127.0.0.1:8200      # cli config
        - VAULT_TOKEN=root                      # cli config
    ```
    This will deploy Hashicorp Vault using its in-memory database.
  - ⚠️ If you plan to run `HYOK Wrapper` in production, comment that block and configure a production-ready Vault instance.
4. 🛠️ Build docker images: `./00-build.sh`
5. 🚀 Run service: `./01-start.sh`
6. 🔄 (Re-) load config: `./02-load-config.sh`
7. 🛑 Stop service: `./03-stop.sh`
8. 🗑️ Remove service: `./04-remove.sh`
