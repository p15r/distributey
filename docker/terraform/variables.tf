variable policies {
  type        = list
  default     = []
  description = "List of policies for external service names. The name corresponds to the 'service' variable with suffix '-transit'"
}

# salesforce tenant
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

# salesforce-dev tenant
variable auth_jwt_dev_path {
  type    = string
  default = "jwt-dev"
}
variable auth_jwt_dev_validation_pubkeys {
  type    = list
  default = []
}
variable auth_jwt_dev_default_role {
  type    = string
  default = "role1"
}
variable auth_jwt_dev_default_role_bound_audiences {
  description = "List of aud claims to match against. Any match is sufficient."
  type        = list
  default     = []
}

variable transit_dev_path {
  type    = string
  default = "transit-dev"
}
variable transit_dev_key_name {
  type    = string
  default = "key3"
}
variable transit_dev_exportable {
  type    = bool
  default = false
}

# monitoring tenant
variable auth_jwt_monitoring_path {
  type    = string
  default = "jwt-monitoring"
}
variable auth_jwt_monitoring_validation_pubkeys {
  type    = list
  default = []
}
variable auth_jwt_monitoring_default_role {
  type    = string
  default = "role2"
}
variable auth_jwt_monitoring_default_role_bound_audiences {
  description = "List of aud claims to match against. Any match is sufficient."
  type        = list
  default     = ["urn:distributey"]
}

variable transit_monitoring_path {
  type    = string
  default = "transit-monitoring"
}

variable transit_monitoring_key_name {
  type    = string
  default = "key2"
}

variable transit_monitoring_exportable {
  type    = bool
  default = false
}
