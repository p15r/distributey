provider "vault" {}

# Vault policies, see folder policies
resource "vault_policy" "policy" {
  for_each = toset(["hyok-pki"])
  name     = each.value
  policy   = file("policies/${each.value}.hcl")
}

resource "vault_mount" "pki" {
  path                      = var.pki_path
  type                      = "pki"
  default_lease_ttl_seconds = var.pki_default_lease_ttl_seconds
  max_lease_ttl_seconds     = var.pki_max_lease_ttl_seconds
}

resource "vault_mount" "transit" {
  path = var.transit_path
  type = "transit"
}

resource "vault_transit_secret_backend_key" "hyok" {
  backend    = vault_mount.transit.path
  name       = var.transit_key_name
  exportable = var.transit_exportable
}

resource "vault_pki_secret_backend_role" "server" {
  backend          = vault_mount.pki.path
  name             = var.pki_role_name_server
  allow_subdomains = var.pki_role_allow_subdomains
  allowed_domains  = var.pki_role_allowed_domains
  client_flag      = false
  server_flag      = true
}

resource "vault_pki_secret_backend_role" "client" {
  backend          = vault_mount.pki.path
  name             = var.pki_role_name_client
  allow_subdomains = var.pki_role_allow_subdomains
  allowed_domains  = var.pki_role_allowed_domains
  client_flag      = true
  server_flag      = false
}

resource "vault_pki_secret_backend_root_cert" "ca" {
  backend     = vault_mount.pki.path
  type        = "internal"
  common_name = var.pki_root_cn
  ttl         = var.pki_root_cert_ttl
}

resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "hyok" {
  backend        = vault_auth_backend.approle.path
  role_name      = var.approle_role_name
  token_policies = ["hyok-pki"]
}

resource "vault_approle_auth_backend_role_secret_id" "secretid" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.hyok.role_name
}



# Update the AppRole roleid in the Ansible vars
resource "null_resource" "update_appid" {
  triggers = {
    # when the AppRole role changes
    key_id = vault_approle_auth_backend_role.hyok.id
  }
  provisioner "local-exec" {
    # Write the new roleid
    command = "echo '${vault_approle_auth_backend_role.hyok.role_id}' > /approle/roleid"
  }
}

# Update the AppRole secretid in the Ansible vars
resource "null_resource" "update_secretid" {
  triggers = {
    # when the secretid changes
    key_id = vault_approle_auth_backend_role_secret_id.secretid.id
  }
  provisioner "local-exec" {
    # Write the new secretid
    command = "echo '${vault_approle_auth_backend_role_secret_id.secretid.secret_id}' > /approle/secretid"
  }
}