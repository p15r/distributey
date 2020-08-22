# HYOK-Wrapper
The HYOK Wrapper provides key material, retrieved from a key service, in the JWE format ([RFC7516](https://tools.ietf.org/html/rfc7516)), to a key consumer.

Currently supported integrations:
- Key service: Hashicorp Vault
- Key consumer: Salesforce's [Cache-only Key Service](https://help.salesforce.com/articleView?id=security_pe_byok_cache.htm&type=5)

## Setup
### Prerequisites 📚
- `docker-compose` (v3.7+)
- Certificate for key wrapping from Key Consumer
- TLS cert & key for reverse proxy

### HYOK Wrapper
- Read more [here](docs/hyok_wrapper.md)

### Vault
- Read more [here](docs/vault.md)

## Certificate Authority
- Read more [here](docs/certificate_authority.md)

## Usage
- Read more [here](docs/usage.md)

### Development
Sync code to the `hyok-wrapper` container by executing `./dev/cp_src_docker.sh`. The HTTP server (`gunicorn`) will automatically detect new files and reload them.

## Architecture
- Read more [here](docs/architecture.md)

## Key Consumer Setup
- Read more [here](docs/key_consumer_setup.md)

## Further reading
- Salesforce HYOK format specification: https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5
- Salesforce key wrapper example: https://github.com/forcedotcom/CacheOnlyKeyWrapper
- JWE libs (not used in `HYOK Wrapper`)
  - `pyjwkest`: https://github.com/rohe/pyjwkest
  - `Authlib`: https://docs.authlib.org/en/stable/jose/jwe.html
