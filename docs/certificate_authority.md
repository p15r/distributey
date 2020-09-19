# Certificate Authority
First, get a certificate from your trusted CA, or use the following steps to create a self-signed CA for development purposes:

1. Create CA key:
    ```bash
    openssl genrsa -aes-256-cbc -out myCA.key 4096
    ```
2. Create CA config (`ca.cfg`):
    ```bash
    [req]
    distinguished_name = req_distinguished_name
    prompt = no
    [req_distinguished_name]
    countryName = CH
    stateOrProvinceName = ZH
    localityName = SomeCity
    organizationName = SomeOrg
    organizationalUnitName = SomeOrgUnit
    commonName = example.com
    ```
3. Create CA cert:
    ```bash
    openssl req -x509 -new -nodes -key myCA.key -sha512 -days 3650 -out myCA.crt -config ca.cfg
    ```
4. Verify CA cert:
    ```bash
    openssl x509 -text -noout -in myCA.crt
    ```
5. Create cert key:
    ```bash
    openssl genrsa -aes-256-cbc -out myCert.key 4096
    ```
6. Create cert config (`cert.cfg`):
    ```bash
    [req]
    distinguished_name = req_distinguished_name
    req_extensions = v3_req
    prompt = no
    [req_distinguished_name]
    countryName = CH
    stateOrProvinceName = ZH
    localityName = SomeCity
    organizationName = SomeOrg
    organizationalUnitName = SomeOrgUnit
    commonName = client.example.com
    [v3_req]
    keyUsage = critical, digitalSignature, keyAgreement
    extendedKeyUsage = serverAuth
    subjectAltName = @alt_names
    [alt_names]
    DNS.1 = client1.example.com
    IP.1 = 192.168.1.2
    ```
7. Create cert csr:
    ```bash
    openssl req -new -sha512 -key myCert.key -config cert.cfg -out myCert.csr
    ```
8. Verify cert csr:
    ```bash
    openssl req -noout -text -in myCert.csr
    ```
9. Create cert:
    ```bash
    openssl x509 -req -in myCert.csr -CA myCA.crt -CAkey myCA.key -CAcreateserial -out myCert.crt -days 3650 -sha512 -extfile cert.cfg -extensions 'v3_req'
    ```
10. Verify cert:
    ```bash
    openssl x509 -text -noout -in myCert.crt
    ```
11. Verify cert chain:
    ```bash
    openssl verify -CAfile myCA.crt myCert.crt
    ```
12.  Configure `myCA.crt` for client auth in nginx. (TODO: more detailled explanation)
13.  Upload `myCert.crt` to Salesforce for client auth.
