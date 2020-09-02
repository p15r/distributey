variable services {
  type        = list
  default     = ["salesforce"]
  description = "List of external service names. This corresponds to the 'subj' field of a signed JWT token"
}
variable policies {
  type        = list
  default     = ["salesforce-transit"]
  description = "List of policies for external service names. The name corresponds to the 'service' variable with suffix '-transit'"
}

variable auth_jwt_path {
  type    = string
  default = "jwt"
}
variable auth_jwt_validation_pubkeys {
  type    = list
  default = []
}
variable auth_jwt_default_role {
  type    = string
  default = "role1"
}
variable auth_jwt_default_role_bound_audiences {
  description = "List of aud claims to match against. Any match is sufficient."
  type        = list
  default     = []
}

variable transit_path {
  type    = string
  default = "transit"
}
variable transit_key_name {
  type    = string
  default = "key1"
}
variable transit_exportable {
  type    = bool
  default = false
}

variable pki_root_cn {
  type    = string
  default = "Root"
}
variable pki_root_cert_ttl {
  type    = number
  default = 3600
}
variable approle_role_name {
  type    = string
  default = "role1"
}


variable provider_url {
  type    = string
  default = "https://localhost:8200"
}

variable pki_path {
  type    = string
  default = ""
}

variable pki_default_lease_ttl_seconds {
  type    = number
  default = 3600
}

variable pki_max_lease_ttl_seconds {
  type    = number
  default = 86400
}

variable pki_role_name_server {
  type    = string
  default = "server"
}

variable pki_role_allow_subdomains {
  type    = bool
  default = false
}

variable pki_role_allowed_domains {
  type    = list
  default = []
}
