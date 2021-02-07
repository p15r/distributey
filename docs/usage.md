Set config files permissions# Usage
## Get JWE token
- Issue an HTTP request to retrieve a `jwe` token:
  ```bash
  $ curl -k --no-progress-meter https://vault/v1/salesforce/jwe-kid-salesforce-serviceX?requestId=$(openssl rand -hex 16) -H "Authorization: $(python3 dev/create_jwt.py)" | jq
  {
    "kid": "jwe-kid-salesforce-serviceX",
    "jwe": "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImp3ZS1raWQtc2FsZXNmb3JjZS1zZXJ2aWNlWCIsICJqdGkiOiAibm9uY2UifQ==.ZPlJ1ZIesHRu-RXcGHIqYrfun4sbZTi2DsTY5YS6citlzgFHPBlTlV-EGBPe5QU8ahjqL6X3KpC7iFgWIng2E43v844uI8jFTMJetwYdP3yU7ckdxw73IvaARuG_ZCB_1xpxfxy4GpLE-u5552jKI8bqjUuWeDTD-Nb9DfyTdA6YEK4atZ6q1mZFUpdewtl9oMEag40G_TUb-K0gtScYhiKWpbHnEvtfUzlAka4F8vrmtGI5GUM84dk_40r5YTT-db3z_uqFj2DzYvXgnPxpJK4k6okqUEWuPAf3gZKWY8ftKP5UbDDD5gnElPL1N72-HcSStn2WDtCjFK8dlLBUDNiOVrGVcAm9Pwt4Ae70XDi7708aGbhdZQ7kqib1V5tJKea088_r6LuuralGsMrYV-E3LY2Drxh73pXWTFVLT8SQ5ezUBeAavQl4NoBtd9j4Vw3tHxnMR6P9mZBFf82EaG4ms7DDgSPwHNsLh7It3HxnFDkGr7cituNlEwzIO0EB_MLLvM51TMQKAL6KO8g1MW7FAO5CXayoIwo-IeV9lqjAM8T8MLutDyrOZy9DXRM_zXMBwQyVnP7JAeMV-KLh6dEwUtm6o0zpxRwF9o0d-ZEwrnR4qe6VQOACeTeJaZlKTtoOvE2qG8tA6stvN2s--qTWK2h4IEEM9f5nBLyACHc=.NIwqi-yT54wS74e3.1pR8BPVAmxYy6m2DNlCa5eEAyhKOmfVzWnNQ_59pv10=.WxOpn6Vj3Ib0VYR16SHOCg=="
  }

  # Check protected header (first dot-separated string)
  $ echo "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZCIsICJqdGkiOiAibm9uY2UifQ==" | base64 -d
  {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "jwe-kid-salesforce-serviceX", "jti": "Caexaezieque6doowu6ohghahng6eidi"}
  ```
- In case the host name `vault` is not resolvable in your setup, use `localhost` instead.
- To retrieve the monitoring secret:
  ```bash
  curl -k --no-progress-meter https://vault/v1/monitoring/jwe-kid-monitoring?requestId=$(openssl rand -hex 16) -H "Authorization: $(python3 dev/create_jwt.py -m)" | jq
  ```

## Splunk

If Splunk logging has been enabled in `config/config.json`, use the following Splunk search to discover `distributey` logs: `index=<INDEXNAME> host="distributey"`.

## Debugging
- Create a dummy JWT: `python3 dev/create_jwt.py` (for developers)
- Check if container `distributey`, `nginx` (and `vault` if in developer mode) are running: `docker ps -a`
- Check logs:
  - `distributey`: `journalctl -f -t dy-distributey`
  - `nginx`: `journalctl -f -t dy-nginx`
- Enable debug logs
  - Set `LOG_LEVEL` to `debug` in `distributey/config/config.json`
  - Fix config files permissions: `./02-fix-cfg-perms.sh`
  - Restart container: `docker restart distributey`
- Enable developer mode to log any cryptographic material such as keys, additional authenticated data, initialization vectors, etc.
  - Set `LOG_LEVEL` to `debug` & `DEV_MODE` to `true` in `distributey/config/config.json`
  - Fix config files permissions: `./02-fix-cfg-perms.sh`
  - Restart container: `docker restart distributey`
- To switch from HTTPS (mTLS) to HTTP between Vault and `distributey`, configure `"VAULT_URL": "http://vault:8200"` in `config/config.json`.

## Decrypt JWE
An example JWE to decrypt:
```
eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZC1zYWxlc2ZvcmNlIiwgImp0aSI6ICIzNzQ4OTFiNjg2MmZhNGVjY2RmMzNiYTg5MDBjOWQ2ZSJ9.cNwudQ5B3yJTRsztSbxtKFzZetL_tPOR_343Y8ZU96jO6cgUPAozrraYN9JhOk8tSM-FP7grG-HwlW0aVKPDfcy1GnePOUGCOE48u9gKzkEDXbrVX4QZbDdR9YFdba-UBk6k7fhzLc_FY_O18UzqaqaJhg-SPcDYnE6CBdl-lgqVO7VUf5guE9Jf8ORWwJvNr9n8jC2WaQ2XPhc5hvFCGJHfxDOswWCiQWOFHZuUXDrNp-evFQPm-VglvO-Lem5zvbAKquoYpWdN7uRu1be9_AUJaCNNCtVGaouXw0UUNgt_E54Z7BYgl8bky0fKs0z9shIvya4cTuFvTQv4TuQtGig7d5F0sVXu5EHtdrpVAHtrxf38Fk_NCHvKzJ2uPHYINSincG-TnAOTVsZNz_atv3GJEYfi9XoSF0XeKxZVM0DHJJM34AJpx6mFi5OQckNizqNmSLgYT0K3b0ajUtAmgOeLpWw9nqZqeQaP0Q1YkdX9h_7gtN_OHrbpRYip9nG8h3d17kX1SZpGxMlDb_fxhIufKhGC9BT47zFvNgnFNRENlJXifXVOG5OsoTue8xeZvXmGOaIe3lHGf67R3nYM_zD-VSU8C8pVo9KrVEu-xw8k581mO-OiN82WcHrjkxc77-5cJCtqp3m0w6cbLVwukBfLxiiJw0Pn5srEUpzvgDE=.dpZl1EF4YNayGWht.zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw=.27vOkMxjnnhHN_Cp9xsveQ==¨
```

1. Enable `DEV_MODE` and set `LOG_LEVEL` to `debug` in `distributey/config/config.json` to log secrets.
2. Extract encrypted `dek` from JWE token by getting the second last dot-separated string: `zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw=`
3. Configure and run `dev/decrypt_dek.py` to decrypt the `dek` (data encryption key; the requested key by the key consumer).
