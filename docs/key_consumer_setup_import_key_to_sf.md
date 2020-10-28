# Import Key to Salesforce
> ⚠️⚠ This option is not recommended, because the private key needs to be unnecessarily transmitted over the internet.

- Create own keypair (like `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout dev/tmp/jwt.key -out dev/tmp/jwt.pem -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName/emailAddress=NoEmailAddress"`)
- In case the certificate has been generated using another tool, make sure it is in PEM format. If not, convert it: `openssl x509 -in your-certificate.crt -out dev/tmp/jwt.pem -outform PEM`
- Create keystore [[docs](https://docs.oracle.com/en/database/other-databases/nosql-database/12.2.4.5/security/import-key-pair-java-keystore.html)]
  - Step-by-step:
    ```bash
    cat myCert.crt myCA.crt > import.pem
    openssl pkcs12 -export -in import.pem -inkey myCert.key -name jwtcert > jwt.p12
    keytool -importkeystore -srckeystore jwt.p12 -destkeystore salesforce.jks -srcstoretype pkcs12 -alias jwtcert
    ```
  - Salesforce requires the key store to be generated using Java 8 (`openjdk-8-jre-headless`). If key store is created with Java 11, the following error will occur `Error: Keystore file is corrupted.`.
  - Password for jks must be between 6-8 letters.
  - Upload to Salesforce:
    - Go to `Certificate and Key Management` and click on `Import from Keystore`
    - Select `JKS File` (`salesforce.jks`) and enter the `Keystore Password`
    - If you get the error `Data Not Available. The data you were trying to access could not be found. It may be due to another user deleting the data or a system error.`, then apply the following workaround [[docs](https://developer.salesforce.com/forums/?id=9060G0000005bFJQAY)] (it is unclear why this is required):
      - Create a self-signed cert in keys and cert management.
      - Enable Identity Provider and assigning the self-signed cert to it.
      - Then you would be able to import certificates/JKS.
      - Upload key store again.
