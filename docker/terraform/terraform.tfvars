# corresponds to 'subj' group_claim
services = ["salesforce-cacheonlyservice"]
# policy name matches service name with suffix -transit
policies = ["hyok-pki", "salesforce-cacheonlyservice-transit"]

auth_jwt_default_role                 = "hyok"
auth_jwt_default_role_bound_audiences = ["urn:hyok-wrapper"]
auth_jwt_validation_pubkeys = [<<EOT
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
EOT
  ,
  <<EOT
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1sco81ycmTYgBynXaYkG
U5F5KsUSAl2xE5X08Bwe3HHvN3B4QB33rYYDANV/Nu5KYdQpdW8+bXNVtQPoyIFA
A9V7BqM8Tjfpo8WeUc4N4E0e3oEHoHTTrWsAh5dGzC7tw1v6va+JEnxPtG3124HY
UdO42aFaEw/GMlMhi7Ix5OEBDWdmL9QoOkE5hPVsNgMZuyDwANfI4p4BtJLh/QF4
aB1AsKO9Wo0MotGB0+MGz6Ae40+uXHMjgzwGLNuTlfisBSvGZ0tv4wQekjBuLcLg
3VHRFB1hHC+VEdC9Ccn7H0wtM6eLSIHuEsiGkIqckopqd/qJVT+qT1vbwWr2H3bB
b8znxEG/Fqf4ULUbyZ7taCG66ws9AVDclQhglOA2JfKbvpfQ/iVvzalPRD1Kg8Gu
NXHru/9RJXBn9zWrj+fLjKK2ekI/PBI0z5/3f5/IwkIHHyzzPbgWV9HozuG8s0px
e4VMGuo/9ADDwsEuMuMmTxHJWnKgN6P2z9NFFF9AKnysZ69cqdR8MhPjbnTsV9HT
9qB4jeSYaQJ81TL6gFL2FkgyjLP2GJSc94b1mPnfvhsPKgz3zYQHgJgvAKcZX47F
iekFOa7M9fzp8LcfBhbQbWXZrT71e2qNYLjnGVzDCP/UfoY1lTjjxgL1e+17kNYF
I5b8sU9DwxRyYvzri24fIY0CAwEAAQ==
-----END PUBLIC KEY-----
EOT
]

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
