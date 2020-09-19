# Usage
- Create a dummy JWT: `python3 dev/create_jwt.py`
- Issue an HTTP request against the root directory to retrieve a `jwe` token:
  ```bash
  $ curl -k --no-progress-meter https://127.0.0.1/v1/kid-salesforce?requestId=nonce -H "Authorization: $(python3 dev/create_jwt.py)" | jq
  {
    "kid": "kid",
    "jwe": "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZCIsICJqdGkiOiAibm9uY2UifQ==.NMUv3Kui4-TSQnvKU39vmGPZ8fexJiHck5GPZTboziCy1RzPBUGPeLbP0trGKeRzl9rYQDOoIlNEKYOFSJ6sEF3B2TCprOxSs22q-P3ARrX6fjiPzdwHX09c65W39Ix9xy2aJEejj-lvc2OmNmBp8eMOZO_5z16hDHVfwhdX92Sxdh4-3gHIlI1Cr2ySqYCKUP8XzOPaLyXpq1VKlmaPZeoSkHO8GIU0sJrBXl3dyDc5SfjVIHyMAhM0dM-aiC9OhmaTxmKWDl3hCwsYv2TKyku2GTZvik4cycwUat8C2M2gi9cQsnsed2GpW9NmUW9Q2iVe2hbMZXoWhgn17T8qZ4AbSEZMCDnVKq5vh-i0o3WsN3D_LUPf9PzB1gNUvR5aBhtto69rXNSeacc_pvUAkBo8dug8xh1Jp6ZFNzL88foE_bn1aj7JSV_cCO_yi569MFnOG1eVFH1kD_OtmfUq62OE2hXfjbhBm6A-XrNBzYjxEL1oasmocqaCtWniqDEXy3VQH7trwAMc_5F3tvAkXPeyW35LFPxd5mA4lj2zf6WEq1tlDogbJCF9q8tsRHbUUYSIAidzcXz9aZs1-W5_6IGAthqhPHMULXt59d_UNCmd98RDbUJH-UfOMNi3QItip1rZBp9QPpJzZtDXGJvmffXAsCv6N0C85Ya2P7elP70=.4En4-wR-etKPOaCx.iUW5BCbUiSbQlAOnLZkrkLlbb8kODWt_sSoDTQaEApA=.4otC6CrDbr_hcLcfy3w3xw=="
  }

  # Check protected header
  $ echo "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZCIsICJqdGkiOiAibm9uY2UifQ==" | base64 -d
  {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "kid", "jti": "nonce"}
  ```
  A new `cek` and `jwe token` will be created for every HTTP request.

## Decrypt JWE

An example JWE to decrypt:
```
eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZC1zYWxlc2ZvcmNlIiwgImp0aSI6ICIzNzQ4OTFiNjg2MmZhNGVjY2RmMzNiYTg5MDBjOWQ2ZSJ9.cNwudQ5B3yJTRsztSbxtKFzZetL_tPOR_343Y8ZU96jO6cgUPAozrraYN9JhOk8tSM-FP7grG-HwlW0aVKPDfcy1GnePOUGCOE48u9gKzkEDXbrVX4QZbDdR9YFdba-UBk6k7fhzLc_FY_O18UzqaqaJhg-SPcDYnE6CBdl-lgqVO7VUf5guE9Jf8ORWwJvNr9n8jC2WaQ2XPhc5hvFCGJHfxDOswWCiQWOFHZuUXDrNp-evFQPm-VglvO-Lem5zvbAKquoYpWdN7uRu1be9_AUJaCNNCtVGaouXw0UUNgt_E54Z7BYgl8bky0fKs0z9shIvya4cTuFvTQv4TuQtGig7d5F0sVXu5EHtdrpVAHtrxf38Fk_NCHvKzJ2uPHYINSincG-TnAOTVsZNz_atv3GJEYfi9XoSF0XeKxZVM0DHJJM34AJpx6mFi5OQckNizqNmSLgYT0K3b0ajUtAmgOeLpWw9nqZqeQaP0Q1YkdX9h_7gtN_OHrbpRYip9nG8h3d17kX1SZpGxMlDb_fxhIufKhGC9BT47zFvNgnFNRENlJXifXVOG5OsoTue8xeZvXmGOaIe3lHGf67R3nYM_zD-VSU8C8pVo9KrVEu-xw8k581mO-OiN82WcHrjkxc77-5cJCtqp3m0w6cbLVwukBfLxiiJw0Pn5srEUpzvgDE=.dpZl1EF4YNayGWht.zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw=.27vOkMxjnnhHN_Cp9xsveQ==¨
```

1. Enable `DEV_MODE` and set `LOG_LEVEL` to `debug` to log the secrets.
2. Extract encrypted `dek` from JWE token by getting the second last dot-separated string: `zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw=`
3. Convert `dek` to hex:
   ```python
   # TODO: add this to dev/decrypt_dek.py and make this step obsolete

   import base64

   b64_dek = "zsEdzjYl8vl51XW9njHt7LWU1ARcXTpU8xL3368pUFw="
   print(base64.b64decode(b64_dek).hex)
   ```
4. Configure and run `dev/decrypt_dek.py` to decrypt the `dek`.
