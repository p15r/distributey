[![Known Vulnerabilities](https://snyk.io/test/github/p15r/HYOK-Wrapper/badge.svg)](https://snyk.io/test/github/p15r/HYOK-Wrapper) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=p15r_HYOK-Wrapper&metric=alert_status)](https://sonarcloud.io/dashboard?id=p15r_HYOK-Wrapper)

# HYOK-Wrapper
The HYOK Wrapper acts as a middleman between a key consumer and a key service. It receives requests designated to the key service, fetches key material and sends JWE-wrapped ([RFC7516](https://tools.ietf.org/html/rfc7516)) responses to the consumer.

Currently supported integrations:
- Key services: Hashicorp Vault
- Key consumer: Salesforce's [Cache-only Key Service](https://help.salesforce.com/articleView?id=security_pe_byok_cache.htm&type=5)

## Installation
1. Fulfill prerequisites [[docs](docs/prerequisites.md)]
2. Configure key consumer [[docs](docs/key_consumer_setup.md)]
3. Configure HYOK wrapper [[docs](docs/hyok_wrapper.md)]
4. Use HYOK Wrapper [[docs](docs/usage.md)]


### For developers
- Verify Vault deployment [[docs](docs/vault.md)]
- Sync source code into container `hyok-wrapper`: `./dev/sync_sc.sh`.

## Architecture
- Read more [here](docs/architecture.md)

## Further reading
- Salesforce key wrapper example: https://github.com/forcedotcom/CacheOnlyKeyWrapper
- JWE libs (not used in `HYOK Wrapper`, but good references)
  - `pyjwkest`: https://github.com/rohe/pyjwkest (no longer maintained)
  - `Authlib`: https://docs.authlib.org/en/stable/jose/jwe.html
