# JWT auth backend for monitoring
resource "vault_jwt_auth_backend" "jwt_monitoring" {
  path                   = var.auth_jwt_monitoring_path
  jwt_validation_pubkeys = var.auth_jwt_monitoring_validation_pubkeys
  default_role           = var.auth_jwt_monitoring_default_role
}

resource "vault_jwt_auth_backend_role" "role_monitoring" {
  backend         = vault_jwt_auth_backend.jwt_monitoring.path
  role_name       = var.auth_jwt_monitoring_default_role
  bound_audiences = var.auth_jwt_monitoring_default_role_bound_audiences
  user_claim      = "iss"
  role_type       = "jwt"
  token_policies  = ["default", "monitoring"]
}

# Transit engine for monitoring key
resource "vault_mount" "transit_monitoring" {
  path = var.transit_monitoring_path
  type = "transit"
}

resource "vault_transit_secret_backend_key" "monitoring" {
  backend    = vault_mount.transit_monitoring.path
  name       = var.transit_monitoring_key_name
  exportable = var.transit_exportable
}
