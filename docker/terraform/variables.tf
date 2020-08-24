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

variable pki_role_name_client {
  type    = string
  default = "client"
}

variable pki_role_allow_subdomains {
  type    = bool
  default = false
}

variable pki_role_allowed_domains {
  type    = list
  default = []
}