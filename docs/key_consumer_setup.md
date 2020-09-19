# Key Consumer Setup
Currently, HYOK Wrapper only supports Salesforce as a key consumer.

## Specs
- Salesforce HYOK format specification: [salesforce's cache-only service](https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5)

## Step-by-step
1. Get a developer account: https://developer.salesforce.com/signup
2. Configure `My Domain`: https://help.salesforce.com/articleView?id=domain_name_overview.htm&type=5
3. Configure permission for Key Management: https://trailhead.salesforce.com/en/content/learn/modules/spe_admins/spe_admins_set_up
4. Create Tenant Secret: https://help.salesforce.com/articleView?id=security_pe_ui_setup.htm&type=5
5. Configure Salesforce to authenticate against HYOK Wrapper using a JWT-based token:
   - Create pub/priv keypair for JWT token signing. It is recommended to create a dedicated keypair for every Salesforce service. Two options exist:
      - Create key in Salesforce (**Recommended**)
         - Go to `Certificate and Key Management` and click on `Create self-signed certificate`
         - Define the following values:
            - `Label`: a representative name for the key
            - `Unique Name`: this is the `KID` of the JWT token, thus must be unique. Recommended naming scheme: `jwt_kid_salesforce_serviceX`
            - Configure certificate properties according to [salesforce doc](https://help.salesforce.com/articleView?id=security_pe_byok_generate_cert.htm&type=5)
              - Mark key as `not exportable`
              - Use key size of `4096 bit`
              - Use `platform encryption`
         - Download the public key and save it by its `Unique Name`. This pub key must later be configured in HYOK wrapper (`config/auth/`).
      - Import own key to Salesforce [[docs](key_consumer_setup_import_key_to_sf.md)] (**Not Recommended**)
   - To go `Named Credential` on Salesforce and create `New Named Credential`

      | Config name  | Value |
      | ------------- | ------------- |
      | `Label` & `Name` | Choose appropriate name (e.g. `hyok-wrapper at example.com`). |
      | `URL` | publicly reachable URL of HYOK wrapper. Expected scheme: `https://domainname/apiversion/tenant`. For example `https://hyok-wrapper.example.com/v1/salesforce/`. |
      | `Certificate` | Leave this setting empty. |
      | `Identity type` | Select `Named principal`. |
      | `Authentication protocol` |Select `JWT`. |
      | `Issuer` | Choose appropriate name (e.g. `salesforce`). |
      | `Named Principal Subject` | This is the JWT subject, configure it accordingly. It must also be configured in `config/config.json`. |
      | `Audiences` | Set `urn:hyok-wrapper`|
      | `Token Valid for` | Set short time perion. E.g. `10 Seconds`. |
      | `JWT Signing Certificate` | Select the previously created certificate (`jwt_kid_salesforce_serviceX`) |
      | `Generate Authorization Header` | Check box to activate. |

   - Configure HYOK (a.k.a Cache-only key connection): https://help.salesforce.com/articleView?id=security_pe_byok_cache_callout.htm&type=5

## Example Request from Key Consumer
HTTP request header with JWT token from Salesforce:
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
     "iss": "myCA",
     "sub": "salesforce-cacheonlyservice",
     "aud": "urn:hyok-wrapper",
     "nbf": 1598213299,
     "iat": 1598213299,
     "exp": 1598213599
   }
   ```
## Further reading
- Troubleshoot: https://help.salesforce.com/articleView?id=security_pe_byok_cache_troubleshoot.htm&type=53
