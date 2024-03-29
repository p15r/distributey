## Request JWE token
- Issue an HTTP request to retrieve a `jwe` token:
  ```bash
  $ curl -k --no-progress-meter https://localhost/v1/salesforce/jwe-kid-salesforce-serviceX?requestId=$(openssl rand -hex 16) -H "Authorization: $(python3 dev/create_jwt.py)" | jq
  {
    "kid": "jwe-kid-salesforce-serviceX",
    "jwe": "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImp3ZS1raWQtc2FsZXNmb3JjZS1zZXJ2aWNlWCIsICJqdGkiOiAibm9uY2UifQ==.ZPlJ1ZIesHRu-RXcGHIqYrfun4sbZTi2DsTY5YS6citlzgFHPBlTlV-EGBPe5QU8ahjqL6X3KpC7iFgWIng2E43v844uI8jFTMJetwYdP3yU7ckdxw73IvaARuG_ZCB_1xpxfxy4GpLE-u5552jKI8bqjUuWeDTD-Nb9DfyTdA6YEK4atZ6q1mZFUpdewtl9oMEag40G_TUb-K0gtScYhiKWpbHnEvtfUzlAka4F8vrmtGI5GUM84dk_40r5YTT-db3z_uqFj2DzYvXgnPxpJK4k6okqUEWuPAf3gZKWY8ftKP5UbDDD5gnElPL1N72-HcSStn2WDtCjFK8dlLBUDNiOVrGVcAm9Pwt4Ae70XDi7708aGbhdZQ7kqib1V5tJKea088_r6LuuralGsMrYV-E3LY2Drxh73pXWTFVLT8SQ5ezUBeAavQl4NoBtd9j4Vw3tHxnMR6P9mZBFf82EaG4ms7DDgSPwHNsLh7It3HxnFDkGr7cituNlEwzIO0EB_MLLvM51TMQKAL6KO8g1MW7FAO5CXayoIwo-IeV9lqjAM8T8MLutDyrOZy9DXRM_zXMBwQyVnP7JAeMV-KLh6dEwUtm6o0zpxRwF9o0d-ZEwrnR4qe6VQOACeTeJaZlKTtoOvE2qG8tA6stvN2s--qTWK2h4IEEM9f5nBLyACHc=.NIwqi-yT54wS74e3.1pR8BPVAmxYy6m2DNlCa5eEAyhKOmfVzWnNQ_59pv10=.WxOpn6Vj3Ib0VYR16SHOCg=="
  }

  # Check protected header (first dot-separated string)
  $ echo "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZCIsICJqdGkiOiAibm9uY2UifQ==" | base64 -d
  {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "jwe-kid-salesforce-serviceX", "jti": "Caexaezieque6doowu6ohghahng6eidi"}
  ```
- To retrieve the monitoring secret:
  ```bash
  curl -k --no-progress-meter https://localhost/v1/monitoring/jwe-kid-monitoring?requestId=$(openssl rand -hex 16) -H "Authorization: $(python3 dev/create_jwt.py -m)" | jq
  ```
- To retrieve the salesforce-dev secret:
  ```bash
  curl -k --no-progress-meter https://localhost/v1/salesforce-dev/salesforce-dev?requestId=$(openssl rand -hex 16) -H "Authorization: $(python3 dev/create_jwt.py -d)" | jq
  ```

Note:
- If fetching a secret fails and `distributey` reports `missing client token, on post *v1/auth/jwt/login`, this means the wrong Vault namespace is configured.

## Splunk

If Splunk logging has been enabled in `config/config.json`, use the following Splunk search to discover `distributey` logs: `index=<INDEXNAME> host="distributey"`.

## Debugging
- Create a dummy JWT: `python3 dev/create_jwt.py`
- Check if container `distributey`, `nginx` (and `vault` if in developer mode) are running: `docker ps -a`
- Check logs:
  - `distributey`: `journalctl -f -t dy-distributey`
  - `nginx`: `journalctl -f -t dy-nginx`
- Enable debug logs
  - Set `LOG_LEVEL` to `debug` in `distributey/config/config.json`
  - Restart container: `docker restart distributey`
- Enable developer mode to log any cryptographic material such as keys, additional authenticated data, initialization vectors, etc.
  - Set `LOG_LEVEL` to `debug` & `DEV_MODE` to `true` in `distributey/config/config.json`
  - Restart container: `docker restart distributey`
- To switch from HTTPS (mTLS) to HTTP between Vault and `distributey`, configure `"VAULT_URL": "http://localhost:8200"` in `config/config.json`.

## Development Mode
- Start Vault: `./00-build.sh -d && ./01-start.sh`. Necessary files for the dev setup (`distributey/dev/dev_setup.sh`) are bootstrapped in development mode only (`-d`).
- Create & activate venv: `python3 -m venv venv && source venv/bin/activate`
- Install dependencies: `python3 -m pip install -r requirements.txt -r requirements-dev.txt`
- Adjust config: `"VAULT_URL": "https://localhost:8300"`
  - alternatively, add `127.0.0.1 vault` to `/etc/hosts`
- Run flask dev server: `python3 dev/dev_mode.py`
- Request JWE: `curl -k --no-progress-meter http://localhost:5000/v1/monitoring/jwe-kid-monitoring?requestId=$(openssl rand -hex 16) -H "Authorization: $(python3 dev/create_jwt.py -m)" -H 'x-real-ip: 127.0.0.1' | jq`
- Run tests: `./run_tests -h` (integration tests require Vault connectivity)

## Decrypt JWE
An example JWE to decrypt:
```
eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZC1zYWxlc2ZvcmNlIiwgImp0aSI6ICIzNzQ4OTFiNjg2MmZhNGVjY2RmMzNiYTg5MDBjOWQ2ZSJ9.cNwudQ5B3yJTRsztSbxtKFzZetL_tPOR_343Y8ZU96jO6cgUPAozrraYN9JhOk8tSM-FP7grG-HwlW0aVKPDfcy1GnePOUGCOE48u9gKzkEDXbrVX4QZbDdR9YFdba-UBk6k7fhzLc_FY_O18UzqaqaJhg-SPcDYnE6CBdl-lgqVO7VUf5guE9Jf8ORWwJvNr9n8jC2WaQ2XPhc5hvFCGJHfxDOswWCiQWOFHZuUXDrNp-evFQPm-VglvO-Lem5zvbAKquoYpWdN7uRu1be9_AUJaCNNCtVGaouXw0UUNgt_E54Z7BYgl8bky0fKs0z9shIvya4cTuFvTQv4TuQtGig7d5F0sVXu5EHtdrpVAHtrxf38Fk_NCHvKzJ2uPHYINSincG-TnAOTVsZNz_atv3GJEYfi9XoSF0XeKxZVM0DHJJM34AJpx6mFi5OQckNizqNmSLgYT0K3b0ajUtAmgOeLpWw9nqZqeQaP0Q1YkdX9h_7gtN_OHrbpRYip9nG8h3d17kX1SZpGxMlDb_fxhIufKhGC9BT47zFvNgnFNRENlJXifXVOG5OsoTue8xeZvXmGOaIe3lHGf67R3nYM_zD-VSU8C8pVo9KrVEu-xw8k581mO-OiN82WcHrjkxc77-5cJCtqp3m0w6cbLVwukBfLxiiJw0Pn5srEUpzvgDE=.dpZl1EF4YNayGWht.zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw=.27vOkMxjnnhHN_Cp9xsveQ==¨
```

1. Enable `DEV_MODE` and set `LOG_LEVEL` to `debug` in `distributey/config/config.json` to log secrets.
2. Extract encrypted `dek` from JWE token by getting the second last dot-separated string: `zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw=`
3. Configure and run `dev/decrypt_dek.py` to decrypt the `dek` (data encryption key; the requested key by the key consumer).

## Multi-Tenancy

distributey can be configured to read keys from different Vault Enterprise namespaces.

An example is given in [development mode](#development-mode). After running the `./dev/dev_setup.sh` script, the `config/config.json` will have different keys configured in the following tenants:
* Key `monitoring` in the Vault "tenant" namespace
* Key `salesforce-dev` in the Vault Root namespace

The VAULT config block can either be configured globally (`VAULT` section as sibling of the `TENANT_CFG`) or per distributey tenant backend (under `TENANT_CFG.${TENANT}.backend.VAULT`):
```json
"VAULT": {
  "cacert": "config/myCA.crt",
  "mtls_client_cert": "config/mtls_auth.crt",
  "mtls_client_key": "config/mtls_auth.key",
  "url": "https://vault:8300",
  "namespace": "root",
  "auth_jwt_path": "jwt",
  "default_role": "distributey",
  "transit_path": "transit"
}
```

The namespace is used for authentication (`auth_jwt_path`) and the `transit_path`. JWT auth backend and Transit engine path must reside in the same Vault namespace.

To connect to the Vault default (Root) namespace, configure distributey with `VAULT.namespace="root"` (see example above).

## Dynamic Key ID Mapping between Distributey and Vault

If the key ID (kid) is not explicitly specified with the `TENANT_CFG.${TENANT}.backend` section, distributey will "forward the request as is" and ask Vault if a Transit key with the given name exists.

To make the mapping between the distributey kid and the Vault Transit key explicit, use a configuration similar to this one:
```json
{
  "TENANT_CFG": {
    "monitoring": {
      ...
      "backend": {
        "jwe-kid-monitoring": {
          "key_consumer_cert": "config/backend/distributey_serviceX_key_consumer.crt",
          "vault_path": "monitoring:latest"
        },
        ...
      }
    }
  ...
  }
}
```

The above configuration is taken from [development mode](#development-mode) and explicitly maps the kid "jwe-kid-monitoring" to the Vault key path "monitoring".

The dynamic configuration can be configured using the `backend_wide_key_consumer_cert` key:
```json
  "backend": {
    "backend_wide_key_consumer_cert": "config/backend/distributey_serviceX_key_consumer.crt",
  }
```

In this case, the explicit mapping between JWE kid and `vault_path` is missing and the `backend_wide_key_consumer_cert` is used for any requested kid (to encrypt the AES content encryption key).
