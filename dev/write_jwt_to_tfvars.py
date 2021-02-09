#!/usr/bin/env python3

import re

tfvars: str = ''
with open('docker/terraform/terraform.tfvars', 'r') as f:
    tfvars = f.read()

jwt_pubkey: str = ''
with open('dev/tmp/jwt.pub', 'r') as f:
    jwt_pubkey = f.read().strip()

p = re.compile('auth_jwt_validation_pubkeys = \[.*?\]',
               re.DOTALL)  # noqa: W605
updated_content = p.sub(
    f'auth_jwt_validation_pubkeys = [<<EOT\n{jwt_pubkey}\nEOT\n]', tfvars)

# dev setup: use same jwt keypair for both tenants
p = re.compile('auth_jwt_monitoring_validation_pubkeys = \[.*?\]',
               re.DOTALL)  # noqa: W605
updated_content = p.sub(
    f'auth_jwt_monitoring_validation_pubkeys = [<<EOT\n{jwt_pubkey}\nEOT\n]',
    updated_content)

with open('docker/terraform/terraform.tfvars', 'w') as f:
    f.write(updated_content)
