| SCA & SAST | SAST - SonarCloud | CodeCov | CI |
| ------------- |:-------------:| -----:| ------ |
| [![Known Vulnerabilities](https://snyk.io/test/github/p15r/distributey/badge.svg)](https://snyk.io/test/github/p15r/distributey) | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=p15r_distributey&metric=alert_status)](https://sonarcloud.io/dashboard?id=p15r_distributey) | [![codecov](https://codecov.io/gh/p15r/distributey/branch/main/graph/badge.svg?token=Q15J8T81QB)](https://codecov.io/gh/p15r/distributey) | [![CI](https://github.com/p15r/distributey/actions/workflows/ci.yml/badge.svg)](https://github.com/p15r/distributey/actions/workflows/ci.yml/) |

# distributey
**tl;dr** `distributey` acts as intermediary between a key consumer and a key service. It receives requests from the key consumer, fetches the key material from the key service and sends back JWE-wrapped ([RFC7516](https://tools.ietf.org/html/rfc7516)) responses.

Why does `distributey` (say "duh·stri·byoot·i") exist? Particularly in enterprises, key material is often generated on-premises for compliance & security reasons. Traditionally, HSMs are often used to create and store said key material. However, using the cloud becomes increasingly popular which inevitably leads to the challenge that the on-prem key material must be made available to cloud encryption services. Typically, one of two approaches is used to distribute key material in such a situation: bring your own key (BYOK) or hold your own key (HYOK). BYOK means that the key service actively pushes key material to a key consumer ("the cloud") while HYOK means that the key consumer can request key material from the key service. The rationale behind HYOK is that the key consumer holds the key material in a temporary cache that is flushed frequently. If a specific key is required, it is requested on-demand. Many popular key services do not support HYOK out of the box, which is where `distributey` comes into play. It can be installed "in front of" a key service, serving HYOK requests from key consumers by communicating with the key service on their behalf.

Currently supported integrations:
- Key service: Hashicorp Vault
- Key consumer: Salesforce [Cache-only Key Service](https://help.salesforce.com/articleView?id=security_pe_byok_cache.htm&type=5)

## Installation
1. Fulfill prerequisites [[docs](docs/prerequisites.md)]
2. Configure key consumer [[docs](docs/key_consumer_setup.md)]
3. Configure `distributey`  [[docs](docs/distributey.md)]
4. Use `distributey` [[docs](docs/usage.md)]


### For developers
- Verify Vault deployment [[docs](docs/vault.md)]

## Architecture
- Read more [here](docs/architecture.md)

## Further reading
- JWE libs (not used in `distributey`, but good references)
  - `pyjwkest`: https://github.com/rohe/pyjwkest (no longer maintained)
  - `Authlib`: https://docs.authlib.org/en/stable/jose/jwe.html
