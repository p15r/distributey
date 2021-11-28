#!/usr/bin/env python3

import re

tfvars: str = ''
with open('docker/terraform/terraform.tfvars', 'r') as f:
    tfvars = f.read()

jwt_pubkey_salesforce: str = ''
with open('dev/tmp/jwt.pub', 'r') as f:
    jwt_pubkey_salesforce = f.read().strip()

p = re.compile('auth_jwt_validation_pubkeys = \[.*?\]',     # noqa: W605
               re.DOTALL)
updated_content = p.sub(
    f'auth_jwt_validation_pubkeys = '
    f'[<<EOT\n{jwt_pubkey_salesforce}\nEOT\n]', tfvars)

# dev setup: use same jwt keypair for both tenants
p = re.compile(
    'auth_jwt_monitoring_validation_pubkeys = \[.*?\]',     # noqa: W605
    re.DOTALL)
updated_content = p.sub(
    f'auth_jwt_monitoring_validation_pubkeys = '
    f'[<<EOT\n{jwt_pubkey_salesforce}\nEOT\n]',
    updated_content)

# salesforce-dev tenant
jwt_pubkey_salesforce_dev: str = ''
with open('dev/tmp/jwt-dev.pub', 'r') as f:
    jwt_pubkey_salesforce_dev = f.read().strip()

p = re.compile('auth_jwt_dev_validation_pubkeys = \[.*?\]',     # noqa: W605
               re.DOTALL)
updated_content = p.sub(
    f'auth_jwt_dev_validation_pubkeys = '
    f'[<<EOT\n{jwt_pubkey_salesforce_dev}\nEOT\n]', updated_content)

with open('docker/terraform/terraform.tfvars', 'w') as f:
    f.write(updated_content)
