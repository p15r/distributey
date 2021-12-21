# JWT auth backend for salesforce-dev
resource "vault_jwt_auth_backend" "jwt_salesforce_dev" {
  path                   = var.auth_jwt_dev_path
  jwt_validation_pubkeys = var.auth_jwt_dev_validation_pubkeys
  default_role           = var.auth_jwt_dev_default_role
}

resource "vault_jwt_auth_backend_role" "role_salesforce_dev" {
  backend         = vault_jwt_auth_backend.jwt_salesforce_dev.path
  role_name       = var.auth_jwt_dev_default_role
  bound_audiences = var.auth_jwt_dev_default_role_bound_audiences
  user_claim      = "iss"
  role_type       = "jwt"
  token_policies  = ["default", "salesforce-dev"]
}

# Transit engine for monitoring key
resource "vault_mount" "transit_dev" {
  path = var.transit_dev_path
  type = "transit"
}

resource "vault_transit_secret_backend_key" "salesforce_dev" {
  backend    = vault_mount.transit_dev.path
  name       = var.transit_dev_key_name
  exportable = var.transit_dev_exportable
}

resource "vault_policy" "policy_dev" {
  name     = "salesforce-dev"
  policy   = file("policies/salesforce-dev.hcl")
}
