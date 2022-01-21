# Provider for the Root namespace
provider "vault" {}

# Log to stdout of the container
resource "vault_audit" "test" {
  type = "file"

  options = {
    file_path = "stdout"
  }
}

# Tenant namespace
resource "vault_namespace" "tenant" {
  path = "tenant"
}
# Provider for the tenant namespace
provider "vault" {
  alias     = "tenant"
  namespace = vault_namespace.tenant.path
}

# Vault policies in root namespace, see folder policies
resource "vault_policy" "policy-root" {
  for_each = toset(var.policies)
  name     = each.value
  policy   = file("policies/${each.value}.hcl")
}
# Vault policies in tenant namespace, see folder policies
resource "vault_policy" "policy" {
  for_each = toset(var.policies)
  name     = each.value
  policy   = file("policies/${each.value}.hcl")
  provider = vault.tenant
}

# JWT auth backend
resource "vault_jwt_auth_backend" "jwt" {
  path                   = var.auth_jwt_path
  jwt_validation_pubkeys = var.auth_jwt_validation_pubkeys
  default_role           = var.auth_jwt_default_role
  provider               = vault.tenant
}

resource "vault_jwt_auth_backend_role" "role" {
  backend         = vault_jwt_auth_backend.jwt.path
  role_name       = var.auth_jwt_default_role
  bound_audiences = var.auth_jwt_default_role_bound_audiences
  user_claim      = "iss"
  token_policies  = ["default", "salesforce", "monitoring"]
  role_type       = "jwt"
  provider        = vault.tenant
}

resource "vault_mount" "transit" {
  path     = var.transit_path
  type     = "transit"
  provider = vault.tenant
}

resource "vault_transit_secret_backend_key" "distributey" {
  backend    = vault_mount.transit.path
  name       = var.transit_key_name
  exportable = var.transit_exportable
  provider   = vault.tenant
}