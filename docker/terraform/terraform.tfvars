# corresponds to 'subj' group_claim
services = ["salesforce-cacheonlyservice"]
# policy name matches service name with suffix -transit
policies = ["hyok-pki", "salesforce-cacheonlyservice-transit"]

auth_jwt_default_role                 = "hyok"
auth_jwt_default_role_bound_audiences = ["urn:hyok-wrapper"]
auth_jwt_validation_pubkeys = [LIST_OF_CERTS]

pki_path                      = "HYOK-Wrapper"
pki_root_cert_ttl             = 315360000 # 10 years
pki_max_lease_ttl_seconds     = 220752000 # 7 years
pki_default_lease_ttl_seconds = 157680000 # 5 years
pki_root_cn                   = "Root CA"
pki_role_allowed_domains      = ["hyok.vt.ch"]
pki_role_allow_subdomains     = true
approle_role_name             = "hyok"
transit_key_name              = "salesforce"
transit_exportable            = true
