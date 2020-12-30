# Key Consumer Setup
Currently, `distributey` only supports Salesforce as a key consumer.

⚠️ Security Note: The on-boarding process of the key consumer is crucial. It creates the trust between `distributey` and the key consumer. Every subsequent transaction (e.g. key material distribution) is based on this initial trust. Therefore, it is vital that the key consumer properly protects the private key of the key consumer certificate. Further, the key consumer public certificate's actual origin should be cryptographically verified before adding it to `distributey`. Installing a public key from an undisclosed/improperly identified origin could lead to compromise of key material.

## Specs
- Salesforce HYOK format specification: [[docs](https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5)]

## Prerequisites
1. Get a developer account: [[docs](https://developer.salesforce.com/signup)]
2. Configure `My Domain`: [[docs](https://help.salesforce.com/articleView?id=domain_name_overview.htm&type=5)]
3. Configure permission for Key Management: [[docs](https://trailhead.salesforce.com/en/content/learn/modules/spe_admins/spe_admins_set_up)]
4. Create `Tenant Secret`: [[docs](https://help.salesforce.com/articleView?id=security_pe_ui_setup.htm&type=5)]

## Step-by-step
### Key Consumer Authentication
Configure Salesforce to authenticate against `distributey` using a JWT-based token.

1. Create pub/priv keypair for `JWT` token signing. It is recommended to create a dedicated keypair for every Salesforce service. Two options exist:
   - Create key in Salesforce (**Recommended**)
     - Go to `Certificate and Key Management` and click on `Create self-signed certificate`
     - Configure the following settings:
       - `Label`: a representative name for the key
       - `Unique Name`: this is the `KID` of the `JWT` token, thus must be unique. Recommended naming scheme: `jwt_kid_salesforce_serviceX`
     - Download the certificate and save it by its `Unique Name`. It must later be configured in `distributey` (`config/auth/`).
     - Salesforce provides a certificate from which `distributey` only needs its public key. Use this command to extract it: `openssl x509 -pubkey -noout -in jwt_kid_salesforce_serviceX.crt > jwt_kid_salesforce_serviceX.pub`
   - Import your own key to Salesforce [[docs](key_consumer_setup_import_key_to_sf.md)] (**Not Recommended**)
2. To go `Named Credential` on Salesforce and create a `New Named Credential` as following:
   | Config name  | Value |
   | ------------- | ------------- |
   | `Label` & `Name` | Choose appropriate name (e.g. `distributey at example.com`). |
   | `URL` | publicly reachable URL of `distributey`. Expected scheme: `https://domainname/apiversion/tenant`. For example `https://distributey.example.com/v1/salesforce/`. |
   | `Certificate` | Leave this setting empty. |
   | `Identity type` | Select `Named principal`. |
   | `Authentication protocol` |Select `JWT`. |
   | `Issuer` | Choose appropriate name (e.g. `salesforce`). |
   | `Named Principal Subject` | This is the JWT subject, configure it accordingly. It must also be configured in `config/config.json`. For example `cacheonlyservice`. |
   | `Audiences` | Set `urn:distributey`|
   | `Token Valid for` | Set short time perion. E.g. `10 Seconds`. |
   | `JWT Signing Certificate` | Select the previously created certificate (`jwt_kid_salesforce_serviceX`) |
   | `Generate Authorization Header` | Check box to activate. |
3. Configure `distributey` (a.k.a Cache-only key connection) [[docs](https://help.salesforce.com/articleView?id=security_pe_byok_cache_callout.htm&type=5)]:
   - Create key wrapping certificate
     - Go to `Security Controls` -> `Certificate and Key Management` and click on `Create Self-Signed Certificate`.
     - Set `Label`/`Unique Name` to something meaningful. For example `distributey-key-consumer_cert`.
     - Configure certificate properties [[docs](https://help.salesforce.com/articleView?id=security_pe_byok_generate_cert.htm&type=5)]
       - Mark key as `not exportable`
       - Use key size of `4096 bit`
       - Use `platform encryption`
   - Configure cache-only key service
     - Go to `Security Controls` -> `Platform Encryption` -> `Key Management` and click on `Generate Tenant Secret` if none exists.
       - ⚠️ Depending on your organization's service contracts, this action might lock the import of any further certificates, including `Bring Your Own Key`, for 4h to 24h.
     - Go to `Security Controls` -> `Platform Encryption` -> `Advanced Settings` and enable `Allow Cache-Only Keys with BYOK` & `Enable Replay Detection for Cache-Only Keys`.
     - Go to `Security Controls` -> `Platform Encryption` -> `Key Management` and click on `Bring Your Own Key`.
     - Select key consumer certificate (`distributey-key-consumer_cert`)
     - Select `Use a Cache-Only Key`
     - Set `Unique Key Identifier` to something meaningful. For example `jwe-kid-salesforce-serviceX`.
     - Select `Named Credential` that was previously created (`distributey at example.com`)

## Example Request from Key Consumer
HTTP request header with JWT token from Salesforce:
   ```
   X-Real-Ip: 85.222.150.8
   Host: up-distributey
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
     "iss": "salesforce",
     "sub": "cacheonlyservice",
     "aud": "urn:distributey",
     "nbf": 1598213299,
     "iat": 1598213299,
     "exp": 1598213599
   }
   ```
## Further reading
- Troubleshoot: [[docs](https://help.salesforce.com/articleView?id=security_pe_byok_cache_troubleshoot.htm&type=53)]
