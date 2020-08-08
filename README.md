# HYOK-Wrapper
The HYOK Wrapper provides key material, retrieved from a key service, wrapped and in the JWE format.

## Setup
- Build docker image: `./build.sh`
- Run docker image: `./run.sh`

## Usage

Next, iusse an HTTP request against the `/` (root) directory and retrieve a jwe token:
```bash
$ curl -k https://127.0.0.1 | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   630  100   630    0     0  27391      0 --:--:-- --:--:-- --:--:-- 27391
{
  "kid": "7c0a90c5-97c0-4d58-8e7e-47070eaa4cbc",
  "jwe": "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogIjdjMGE5MGM1LTk3YzAtNGQ1OC04ZTdlLTQ3MDcwZWFhNGNiYyJ9.Fx187fQiRtrGDcObWuL_jDCLwYaJ1dAANBczv9d2jZpb7V68qSt8snHbeKnJ48LtBP1cTiM0bfsdZFrcqJT3mZHR0JyGqqM2VEuUVxkij_f3HwU5phOuu7YGsy7FQmnmjOpWLw1JQ7Ut_wfJ-qGUPx3wWCMsrk6KO9FpxwQ8OIx2pBjcMVwRzdLL14lwv3TZXP_Hc4WW7JpaOGK6CblwkjZFBMzfKLqMviY5WLMpeDlbW3tARFCoBc7dgKjhiqjht0cpLzvsq1cPTv_kYzUW6TwpbWkGS7-024HGTG4LI3daP7tCD1ck0MKQQLMh3yiyoMjSAWT2lwO7BUz3EvlqaQ==.MfJWE7Tnw-SvSOr08b5xmA==.atmlDpJpucNtYUwCDCd0otKLLr2pIFg376r-fcaQ0ImWLAIRhgg5MAy9Cspzg_j9.GkOSt7-NPulOlCSPPncrCw=="
}
```

Check the generated `d`ek, `cek` & `jwe token` in the `output/` dir:
```bash
$ ls output/
cek-2020-08-08_14:52:20  dek-2020-08-08_14:52:20  json_jwe_token-2020-08-08_14:52:20.json
```
A `dek`, `cek` and `jwe token` will be created for every HTTP request.

## Further reading
- Salesforce HYOK format specification: https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5
- Salesforce example key wrapper: https://github.com/forcedotcom/CacheOnlyKeyWrapper
- JSON Web Encryption (JWE) RFC: https://tools.ietf.org/html/rfc7516
- Authlib: https://docs.authlib.org/en/stable/jose/jwe.html
