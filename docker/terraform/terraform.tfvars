# corresponds to 'sub' group_claim
services = ["cacheonlyservice"]
# policy name matches service name with suffix -transit
policies = ["distributey-pki", "cacheonlyservice-transit"]

auth_jwt_default_role                 = "distributey"
auth_jwt_default_role_bound_audiences = ["urn:distributey"]
auth_jwt_validation_pubkeys = [<<EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqDlq7rqgsWuKCm0LJe9m
VdX0By6g3YAeL/4mUkM4Z8+HeT1zInD2/TpW86CpNfo/KZjlVRFxLnjwUmYFJwo9
3NHJPxPTkOX7IxFlqZPiAbnijnIlpCtT6Gw4QYlpok6vI5so2pBqvKo1Nc7NmQ+a
cC2YB/fbiodWBogXwPR2b8OpLrP4tnWmYXP4Eu+q3iDE8kZo68vHjau1ux/JaYCr
yImXn2A3jGkMDQkhrWK6T/zhnmJL27wMDyTdFRVEUiEumTyHpMeGg8ySpG8CiOYk
qwdW9DdlEPakLSzq3MHRSrCmjoqSssjxc8oLNJTCHPWtqlWRokKW8hUWjiYLdxEJ
VQIDAQAB
-----END PUBLIC KEY-----
EOT
]

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
