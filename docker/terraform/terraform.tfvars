# salesforce tenant
policies = ["salesforce"]

auth_jwt_default_role                 = "distributey"
auth_jwt_default_role_bound_audiences = ["urn:distributey"]
auth_jwt_validation_pubkeys = [LIST_OF_CERTS]

transit_key_name              = "salesforce"
transit_exportable            = true

# monitoring tenant
auth_jwt_monitoring_default_role = "monitoring"
auth_jwt_monitoring_validation_pubkeys = [LIST_OF_MONITORING_CERTS]
