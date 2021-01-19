# Full configuration options can be found at https://www.vaultproject.io/docs/configuration

# HTTP listener
#listener "tcp" {
#  address = "0.0.0.0:8200"
#  tls_disable = "true"
#}

# mTLS listener
listener "tcp" {
  address = "0.0.0.0:8300"
  # TLS server cert file
  tls_cert_file = "/vault/config/vault_combined.pem"
  # TLS server key file
  tls_key_file = "/vault/config/vault.key"
  # Turns on client authentication for this listener
  tls_require_and_verify_client_cert = "true"
  # PEM-encoded Certificate Authority file used for checking the authenticity of client
  tls_client_ca_file = "/vault/config/myCA.crt"
}