#!/usr/bin/env bash

set -euf -o pipefail

tls_cfg_path="dev/tls"
tmp_path="dev/tmp"
ca_passphrase="foobar"
cert_passphrase="foobar2"

[ ! -d "$tmp_path/" ] && mkdir $tmp_path/

# CA
echo "🔑 Generate CA key..."
openssl genrsa -passout pass:$ca_passphrase -aes-256-cbc -out $tmp_path/myCA.key 4096

echo "🔑 Generate CA certificate..."
openssl req -x509 -passin pass:$ca_passphrase -new -nodes -key $tmp_path/myCA.key -sha512 -days 3650 -out $tmp_path/myCA.crt -config $tls_cfg_path/ca.cfg

# NGINX
echo "🔑 Generate NGINX cert key..."
openssl genrsa -passout pass:$cert_passphrase -aes-256-cbc -out $tmp_path/nginx_pw.key 4096

echo "🔓 Remove passphrase from NGINX key..."
openssl rsa -passin pass:$cert_passphrase -in $tmp_path/nginx_pw.key -out $tmp_path/nginx.key

echo "🔑 Generate NGINX cert csr..."
openssl req -passin pass:$cert_passphrase -new -sha512 -key $tmp_path/nginx.key -config $tls_cfg_path/request.cfg -out $tmp_path/nginx.csr

echo "🔑 Generate NGINX cert..."
openssl x509 -passin pass:$ca_passphrase -req -in $tmp_path/nginx.csr -CA $tmp_path/myCA.crt -CAkey $tmp_path/myCA.key -CAcreateserial -out $tmp_path/nginx.crt -days 3650 -sha512 -extfile $tls_cfg_path/request.cfg -extensions 'v3_req'

# Key Consumer Key
echo "🔑 Generate key consumer key..."
openssl genrsa -passout pass:$cert_passphrase -aes-256-cbc -out $tmp_path/key_consumer_key_pw.key 4096

echo "🔓 Remove passphrase from key consumer key..."
openssl rsa -passin pass:$cert_passphrase -in $tmp_path/key_consumer_key_pw.key -out $tmp_path/key_consumer_key.key

echo "🔑 Generate key consumer key cert csr..."
openssl req -passin pass:$cert_passphrase -new -sha512 -key $tmp_path/key_consumer_key.key -config $tls_cfg_path/request.cfg -out $tmp_path/key_consumer_key.csr

echo "🔑 Generate key consumer cert..."
openssl x509 -passin pass:$ca_passphrase -req -in $tmp_path/key_consumer_key.csr -CA $tmp_path/myCA.crt -CAkey $tmp_path/myCA.key -CAcreateserial -out $tmp_path/key_consumer_key.crt -days 3650 -sha512 -extfile $tls_cfg_path/request.cfg -extensions 'v3_req'

# JWT - salesforce
echo "🔑 Generate salesforce JWT key..."
openssl genrsa -passout pass:$cert_passphrase -aes-256-cbc -out $tmp_path/jwt_pw.key 4096

echo "🔓 Remove passphrase from salesforce JWT key..."
openssl rsa -passin pass:$cert_passphrase -in $tmp_path/jwt_pw.key -out $tmp_path/jwt.key

echo "🔑 Generate salesforce JWT cert csr..."
openssl req -passin pass:$cert_passphrase -new -sha512 -key $tmp_path/jwt.key -config $tls_cfg_path/request.cfg -out $tmp_path/jwt.csr

echo "🔑 Generate salesforce JWT cert..."
openssl x509 -passin pass:$ca_passphrase -req -in $tmp_path/jwt.csr -CA $tmp_path/myCA.crt -CAkey $tmp_path/myCA.key -CAcreateserial -out $tmp_path/jwt.crt -days 3650 -sha512 -extfile $tls_cfg_path/request.cfg -extensions 'v3_req'

echo "🔨 Export pubkey from salesforce JWT cert..."
openssl x509 -pubkey -noout -in $tmp_path/jwt.crt > $tmp_path/jwt.pub

# JWT - salesforce-dev
echo "🔑 Generate salesforce-dev JWT key..."
openssl genrsa -passout pass:$cert_passphrase -aes-256-cbc -out $tmp_path/jwt_pw-dev.key 4096

echo "🔓 Remove passphrase from salesforce-dev JWT key..."
openssl rsa -passin pass:$cert_passphrase -in $tmp_path/jwt_pw-dev.key -out $tmp_path/jwt-dev.key

echo "🔑 Generate salesforce-dev JWT cert csr..."
openssl req -passin pass:$cert_passphrase -new -sha512 -key $tmp_path/jwt-dev.key -config $tls_cfg_path/request.cfg -out $tmp_path/jwt-dev.csr

echo "🔑 Generate salesforce-dev JWT cert..."
openssl x509 -passin pass:$ca_passphrase -req -in $tmp_path/jwt-dev.csr -CA $tmp_path/myCA.crt -CAkey $tmp_path/myCA.key -CAcreateserial -out $tmp_path/jwt-dev.crt -days 3650 -sha512 -extfile $tls_cfg_path/request.cfg -extensions 'v3_req'

echo "🔨 Export pubkey from salesforce-dev JWT cert..."
openssl x509 -pubkey -noout -in $tmp_path/jwt-dev.crt > $tmp_path/jwt-dev.pub

# Vault mTLS auth
echo "🔑 Generate mTLS auth cert key..."
openssl genrsa -passout pass:$cert_passphrase -aes-256-cbc -out $tmp_path/mtls_auth_pw.key 4096

echo "🔓 Remove passphrase from mTLS auth key..."
openssl rsa -passin pass:$cert_passphrase -in $tmp_path/mtls_auth_pw.key -out $tmp_path/mtls_auth.key

echo "🔑 Generate mTLS auth cert csr..."
openssl req -passin pass:$cert_passphrase -new -sha512 -key $tmp_path/mtls_auth.key -config $tls_cfg_path/request.cfg -out $tmp_path/mtls_auth.csr

echo "🔑 Generate mTLS auth cert..."
openssl x509 -passin pass:$ca_passphrase -req -in $tmp_path/mtls_auth.csr -CA $tmp_path/myCA.crt -CAkey $tmp_path/myCA.key -CAcreateserial -out $tmp_path/mtls_auth.crt -days 3650 -sha512 -extfile $tls_cfg_path/request.cfg -extensions 'mtls_client'

# Vault server TLS
echo "🔑 Generate Vault cert key..."
openssl genrsa -passout pass:$cert_passphrase -aes-256-cbc -out $tmp_path/vault_pw.key 4096

echo "🔓 Remove passphrase from Vault key..."
openssl rsa -passin pass:$cert_passphrase -in $tmp_path/vault_pw.key -out $tmp_path/vault.key

echo "🔑 Generate Vault cert csr..."
openssl req -passin pass:$cert_passphrase -new -sha512 -key $tmp_path/vault.key -config $tls_cfg_path/request.cfg -out $tmp_path/vault.csr

echo "🔑 Generate Vault cert..."
openssl x509 -passin pass:$ca_passphrase -req -in $tmp_path/vault.csr -CA $tmp_path/myCA.crt -CAkey $tmp_path/myCA.key -CAcreateserial -out $tmp_path/vault.crt -days 3650 -sha512 -extfile $tls_cfg_path/request.cfg -extensions 'v3_req_vault'

echo " Concatenate Vault cert with CA file"
echo " The primary certificate should appear first in the combined file."
cat $tmp_path/vault.crt $tmp_path/myCA.crt > $tmp_path/vault_combined.pem

# Copy keys and certs to places...
# Hack: add pubkey to tfvars. Terraform should read pubkey file instead.
echo 'Adding JWT to Terraform config...'
python3 dev/write_jwt_to_tfvars.py
echo 'Copying config...'
cp dev/example-config.json config/config.json
echo 'Copying salesforce JWT public key...'
[ -f config/auth/jwt_salesforce_serviceX.pub ] && chmod 600 config/auth/jwt_salesforce_serviceX.pub
cp $tmp_path/jwt.pub config/auth/jwt_salesforce_serviceX.pub
echo 'Copying salesforce-dev JWT public key...'
[ -f config/auth/jwt_salesforce_serviceX-dev.pub ] && chmod 600 config/auth/jwt_salesforce_serviceX-dev.pub
cp $tmp_path/jwt-dev.pub config/auth/jwt_salesforce_serviceX-dev.pub
echo 'Copying self-signed certs for API...'
cp $tmp_path/nginx.{key,crt} docker/certs/
echo 'Copying salesforce key consumer cert & key...'
[ -f config/backend/distributey_serviceX_key_consumer.crt ] && chmod 600 config/backend/distributey_serviceX_key_consumer.crt
cp $tmp_path/key_consumer_key.crt config/backend/distributey_serviceX_key_consumer.crt
echo 'Copying salesforce-dev key consumer cert & key...'
[ -f config/backend/distributey_allservices_key_consumer-dev.crt ] && chmod 600 config/backend/distributey_allservices_key_consumer-dev.crt
cp $tmp_path/key_consumer_key.crt config/backend/distributey_allservices_key_consumer-dev.crt
echo 'Copying Vault mTLS auth cert/key and CA for distributey hvac client...'
cp $tmp_path/mtls_auth.crt $tmp_path/mtls_auth.key $tmp_path/myCA.crt config/
echo 'Copying Vault mTLS server CA to Vault config folder...'
cp $tmp_path/myCA.crt docker/vault/
echo 'Copying Vault server cert & key to vault config folder...'
cp $tmp_path/vault_combined.pem $tmp_path/vault.key docker/vault/
