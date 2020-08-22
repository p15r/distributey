# Vault
- Verify: `docker exec vault vault read transit/keys/salesforce`
- Todo
  - Configure TTL for key in accordance to Salesforce cache-only key policy?
  - Current configuration provides the same key for every request from Salesforce instead of generating a new one each time.
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
