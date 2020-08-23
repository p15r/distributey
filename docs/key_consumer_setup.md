# Key Consumer Setup
Currently, HYOK Wrapper only supports Salesforce as a key consumer.

Specs
- Salesforce HYOK format specification: https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5

Step-by-step
1. Get a developer account: https://developer.salesforce.com/signup
2. Configure `My Domain`: https://help.salesforce.com/articleView?id=domain_name_overview.htm&type=5
3. Configure permission for Key Management: https://trailhead.salesforce.com/en/content/learn/modules/spe_admins/spe_admins_set_up
4. Create Tenant Secret: https://help.salesforce.com/articleView?id=security_pe_ui_setup.htm&type=5
5. How to configure HYOK (a.k.a Cache-only key connection): https://help.salesforce.com/articleView?id=security_pe_byok_cache_callout.htm&type=5
6. Configure JWT auth: tbd
   1. upload cert & key to Salesforce to sign JWT tokens
      1. [create](certificate_authority.md) CA
      2. Create keystore with cert & key: https://docs.oracle.com/en/database/other-databases/nosql-database/12.2.4.5/security/import-key-pair-java-keystore.html
         1. Step-by-step:
         ```bash
         cat mtls/myCert.crt mtls/myCA.crt > import.pem
         openssl pkcs12 -export -in import.pem -inkey mtls/myCert.key -name jwtcert > jwt.p12
         keytool -importkeystore -srckeystore jwt.p12 -destkeystore salesforce.jks -srcstoretype pkcs12 -alias jwtcert
         ```
         2. Only works with Java 8! Not 11 [openjdk-8-jre-headless]. If you upload a jks created with Java 11, you will get "Error: Keystore file is corrupted."
         3. Password for jks must be between 6-8 letters.
      3. Upload to Salesforce: tbd
         1. if you get the error "Data Not Available The data you were trying to access could not be found. It may be due to another user deleting the data or a system error.", then apply the following workaround (https://developer.salesforce.com/forums/?id=9060G0000005bFJQAY):
            1. Create a self-signed cert in keys and cert management.
            2. Enable Identity Provider and assigning the self-signed cert to it.
            3. Then you would be able to import certificates/JKS.
   2. To go "Named Credential" on Salesforce and select desired credential
   3. Enable JWT token-based authentication: ![named credential w/ JWT-based auth](named-credential-jwt-auth.png)
   4. Example HTTP request header with JWT token from salesforce:
   ```
   X-Real-Ip: 85.222.150.8
   Host: up-hyok-wrapper
   Connection: close
   Authorization: Bearer eyJraWQiOiJqd3RjZXJ0IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJpc3N1ZXItbXlDQSIsInN1YiI6InN1YmplY3Qtc2FsZXNmb3JjZSIsImF1ZCI6InVybjogc2FsZXNmb3JjZSIsIm5iZiI6MTU5ODIxMzI5OSwiaWF0IjoxNTk4MjEzMjk5LCJleHAiOjE1OTgyMTM1OTl9.iEyt5mqXvWKvQ3d-eLcIhVb53oEIie9ecXYSB_y5zumPA9tHD5PMWArikskSz30-T5d2NQ0WFHXSWHRd3BWMvwph75gRXCwojGoXdoBT20mmF2r8zkgy3bbNx-1kjCHU7ErV2eJO0tRORvQ-5JjSosTpJw7kw3LlHVHLRvK9PPxwvfAWwaAO3flPvN08LLImQU2M-2No_5MgNpun4zxCC0J7F9cTNZXVbmX5lGsBdBBnrFJgyNjFpsFzaBZAJhEtXvUwokriPQQ6msuWRTJzutQr1oKljJUg7QpMbiBPYJJcPFSG-nnlhWAFThENcUD4SESfhvavaNdV_UEYMX6rmKCFi-6b8F2-1xBQQyH4sYlUWb1PoDMSllT5V4IhES0JnsR81cFK6wkbheMao2ZdTzlVTgoHRosdNq2c87DjPtTpiKDeROITdF2T34Z3nPH-pYw0OttF1z6dm9I96MB5lj36V2k_40AEdaSHqsGk4_43TOtmDYnYFNikx_dQHDz2y4ty6sIqiNv1hs34w0LbYMFkgdqNsbeJ4iH1rCaLI-VJwT-E1mhs-1ATLtuTq10BB5mvEK6LNUVuvttn36Mq4b6r01hy9BaKkitNsSbbXGFunLOKVNgf_BEtcvy7OkhMiXBQsEgFL6ladDn-N2R5K9ZlKOJFRbDNJOh9iec4yd0
   User-Agent: SFDC-Callout/49.0
   Cache-Control: no-cache
   Pragma: no-cache
   Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
   ```
   Example JWT header:
   ```json
   {
     "kid": "jwtcert",
     "typ": "JWT",
     "alg": "RS256"
   }
   ```
   Example JWT payload:
   ```json
   {
     "iss": "issuer-myCA",
     "sub": "subject-salesforce",
     "aud": "urn: salesforce",
     "nbf": 1598213299,
     "iat": 1598213299,
     "exp": 1598213599
   }
   ```
Further reading
- Troubleshoot: https://help.salesforce.com/articleView?id=security_pe_byok_cache_troubleshoot.htm&type=53
