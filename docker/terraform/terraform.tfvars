# corresponds to 'sub' group_claim
services = ["cacheonlyservice"]
# policy name matches service name with suffix -transit
policies = ["distributey-pki", "cacheonlyservice-transit"]

auth_jwt_default_role                 = "distributey"
auth_jwt_default_role_bound_audiences = ["urn:distributey"]
auth_jwt_validation_pubkeys = [LIST_OF_CERTS]

pki_path                      = "distributey"
pki_root_cert_ttl             = 315360000 # 10 years
pki_max_lease_ttl_seconds     = 220752000 # 7 years
pki_default_lease_ttl_seconds = 157680000 # 5 years
pki_root_cn                   = "Root CA"
pki_role_allowed_domains      = ["distributey.vt.ch"]
pki_role_allow_subdomains     = true
approle_role_name             = "distributey"
transit_key_name              = "salesforce"
transit_exportable            = true
