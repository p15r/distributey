[![Known Vulnerabilities](https://snyk.io/test/github/p15r/HYOK-Wrapper/badge.svg)](https://snyk.io/test/github/p15r/HYOK-Wrapper) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=p15r_HYOK-Wrapper&metric=alert_status)](https://sonarcloud.io/dashboard?id=p15r_HYOK-Wrapper) [![deepcode](https://www.deepcode.ai/api/gh/badge?key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbGF0Zm9ybTEiOiJnaCIsIm93bmVyMSI6InAxNXIiLCJyZXBvMSI6IkhZT0stV3JhcHBlciIsImluY2x1ZGVMaW50IjpmYWxzZSwiYXV0aG9ySWQiOjIzNDgyLCJpYXQiOjE2MDE4MzYyMzh9.e7JvLeaIRNHYKuncpEPzBC6qYibCS46Lj3AG4sRAqmQ)](https://www.deepcode.ai/app/gh/p15r/HYOK-Wrapper/_/dashboard?utm_content=gh%2Fp15r%2FHYOK-Wrapper)

# HYOK-Wrapper
**tl;dr** The HYOK Wrapper acts as a middleman between a key consumer and a key service. It receives requests designated to the key service, fetches key material and sends JWE-wrapped ([RFC7516](https://tools.ietf.org/html/rfc7516)) responses to the consumer.

Why does `HYOK Wrapper` exist? Particularly in enterprises, key material (passwords, certificates, etc.) is often generated on-premises for compliance & security reasons. Traditionally, HSMs are commonly used to generate and store key material. Using the cloud becomes increasingly popular which inevitably leads to the challenge that on-premises generated key material must be made available to cloud encryption services. Typically, either of two approaches is used to distribute key material: bring your own key (boyk) or hold your own key (hyok). BYOK means that the key services actively pushes key material to a key consumer while HYOK means that the key consumer can request key material from the key service. The idea of HYOK is that the key consumer holds the key material in a temporary cache that is flushed frequently and if a specific key is required, it is requested on-demand. Many popular key services do not support HYOK out of the box, which is where the `HYOK Wrapper` comes into play. It can be installed "in front of" a key service, serving HYOK requests from key consumers by communicating with the key service on their behalf.

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
