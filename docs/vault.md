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
