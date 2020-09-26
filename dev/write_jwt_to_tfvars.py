#!/usr/bin/env python3
import re

tfvars: str = ''
with open('docker/terraform/terraform.tfvars', 'r') as f:
    tfvars = f.read()

jwt_pubkey: str = ''
with open('dev/tmp/jwt.pub', 'r') as f:
    jwt_pubkey = f.read().strip()

p = re.compile('auth_jwt_validation_pubkeys = \[.*?\]', re.DOTALL)  # noqa: W605
replaced = p.sub(f'auth_jwt_validation_pubkeys = [<<EOT\n{jwt_pubkey}\nEOT\n]', tfvars)

with open('docker/terraform/terraform.tfvars', 'w') as f:
    f.write(replaced)
