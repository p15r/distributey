# Architecture
The following workflow is executed when a key consumer requests key material:

1. The key consumer requests key material by issuing an HTTP GET request to `HYOK Wrapper`. Its request contains the key identified (`kid`) and optionally a `nonce` to prevent reply attacks.
2. `HYOK Wrapper` retrieves the key material identified by the `kid` from the key service.
3. `HYOK Wrapper` creates a `JWE`.
4. The key consumer unwraps the key material in the `JWE` and imports it.

The workflow is similar for every key consumer. However, this example illustrates the process for Salesforce.
![workflow](cache-only-key-service-v3.png)
