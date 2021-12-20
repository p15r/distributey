policies = ["salesforce", "salesforce-dev", "monitoring"]

# salesforce tenant
auth_jwt_default_role                 = "distributey"
auth_jwt_default_role_bound_audiences = ["urn:distributey"]
auth_jwt_validation_pubkeys = [LIST_OF_CERTS]

transit_key_name              = "salesforce"
transit_exportable            = true

# salesforce-dev tenant
auth_jwt_dev_default_role                 = "salesforce-dev"
auth_jwt_dev_default_role_bound_audiences = ["urn:distributey"]
auth_jwt_dev_validation_pubkeys = [LIST_OF_DEV_CERTS]

transit_dev_key_name              = "salesforce-dev"
transit_dev_exportable            = true

# monitoring tenant
auth_jwt_monitoring_default_role = "monitoring"
auth_jwt_monitoring_default_role_bound_audiences = ["urn:distributey"]
auth_jwt_monitoring_validation_pubkeys = [LIST_OF_MONITORING_CERTS]

transit_monitoring_key_name = "monitoring"
transit_monitoring_exportable = true
