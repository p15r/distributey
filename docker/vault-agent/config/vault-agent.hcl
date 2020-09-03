# Example Vault agent configuration file with AppRole authentication:
# https://www.vaultproject.io/docs/agent/template#example-configuration

pid_file = "/tmp/vault-agent.pidfile"

vault {
  address = "http://vault:8200"
}

auto_auth {
  method {
    # Authenticate with AppRole
    # https://www.vaultproject.io/docs/agent/autoauth/methods/approle
    type      = "approle"

    config = {
      role_id_file_path = "/approle/roleid"
      secret_id_file_path = "/approle/secretid"
      remove_secret_id_file_after_reading = false
    }
  }

  sink {
    # write Vault token to file
    # https://www.vaultproject.io/docs/agent/autoauth/sinks/file
    type = "file"

    config = {
      # best practice to write the file to a ramdisk (0640)
      # have a look at wrapped token for advanced configuration
      path = "/tmp/vault-agent-token"
    }
  }
}
