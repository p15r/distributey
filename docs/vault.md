# Vault
- UI: `http://localhost:8200`
  - root login token is `root`
- Verify: `docker exec vault vault read transit/keys/salesforce`
- Test your Vault configuration using the Vault cli:
  - ```bash
    docker exec vault \
      vault read -format=json transit/export/encryption-key/salesforce/latest | \
      jq -r ".data.keys[]" > vault-dek.key.base64
    ```
  - ```bash
    docker exec vault \
      vault write -format=json sys/tools/hash/sha2-256 \
      input=$(cat vault-dek.key.base64) | \
      jq -r ".data.sum" > vault-dek.key.hex
    ```

## Audit log

The request coming in from distributey can be verified in the Audit log enabled on the container standard output:
```bash
docker-compose logs -f vault
```

This helps to verify the authentication requests and the requests for keys, which is especially helpful in multi-tenancy scenarios or for troubleshooting permission/policy faults.
