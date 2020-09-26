- Import own key to Salesforce
    > ⚠ This Option is not recommended, because the private key needs to be transmitted.
    - Create own keypair (like `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout dev/tmp/jwt.key -out dev/tmp/jwt.pem -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName/emailAddress=NoEmailAddress"`)
    - Create keystore with cert & key: https://docs.oracle.com/en/database/other-databases/nosql-database/12.2.4.5/security/import-key-pair-java-keystore.html
    - Step-by-step:
        ```bash
        cat mtls/myCert.crt mtls/myCA.crt > import.pem
        openssl pkcs12 -export -in import.pem -inkey mtls/myCert.key -name jwtcert > jwt.p12
        keytool -importkeystore -srckeystore jwt.p12 -destkeystore salesforce.jks -srcstoretype pkcs12 -alias jwtcert
        ```
    - Only works with Java 8! Not 11 [openjdk-8-jre-headless]. If you upload a jks created with Java 11, you will get "Error: Keystore file is corrupted."
    - Password for jks must be between 6-8 letters.
    - Upload to Salesforce:
    - Go to `Certificate and Key Management` and click on `Import from Keystore`
    - Select `JKS File` (`salesforce.jks`) and enter the `Keystore Password`
    - ℹ️ If you get the error "Data Not Available The data you were trying to access could not be found. It may be due to another user deleting the data or a system error.", then apply the following workaround (https://developer.salesforce.com/forums/?id=9060G0000005bFJQAY):
        - Create a self-signed cert in keys and cert management.
        - Enable Identity Provider and assigning the self-signed cert to it.
        - Then you would be able to import certificates/JKS.
