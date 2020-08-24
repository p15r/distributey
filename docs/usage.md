# Usage
Create a dummy JWT: `python3 dev/create_jwt.py`

Issue an HTTP request against the root directory to retrieve a `jwe` token:
```bash
$ curl -k --no-progress-meter https://127.0.0.1/v1/kid?requestId=nonce -H "Authorization: Bearer eyJ0.." | jq
{
  "kid": "kid",
  "jwe": "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZCIsICJqdGkiOiAibm9uY2UifQ==.NMUv3Kui4-TSQnvKU39vmGPZ8fexJiHck5GPZTboziCy1RzPBUGPeLbP0trGKeRzl9rYQDOoIlNEKYOFSJ6sEF3B2TCprOxSs22q-P3ARrX6fjiPzdwHX09c65W39Ix9xy2aJEejj-lvc2OmNmBp8eMOZO_5z16hDHVfwhdX92Sxdh4-3gHIlI1Cr2ySqYCKUP8XzOPaLyXpq1VKlmaPZeoSkHO8GIU0sJrBXl3dyDc5SfjVIHyMAhM0dM-aiC9OhmaTxmKWDl3hCwsYv2TKyku2GTZvik4cycwUat8C2M2gi9cQsnsed2GpW9NmUW9Q2iVe2hbMZXoWhgn17T8qZ4AbSEZMCDnVKq5vh-i0o3WsN3D_LUPf9PzB1gNUvR5aBhtto69rXNSeacc_pvUAkBo8dug8xh1Jp6ZFNzL88foE_bn1aj7JSV_cCO_yi569MFnOG1eVFH1kD_OtmfUq62OE2hXfjbhBm6A-XrNBzYjxEL1oasmocqaCtWniqDEXy3VQH7trwAMc_5F3tvAkXPeyW35LFPxd5mA4lj2zf6WEq1tlDogbJCF9q8tsRHbUUYSIAidzcXz9aZs1-W5_6IGAthqhPHMULXt59d_UNCmd98RDbUJH-UfOMNi3QItip1rZBp9QPpJzZtDXGJvmffXAsCv6N0C85Ya2P7elP70=.4En4-wR-etKPOaCx.iUW5BCbUiSbQlAOnLZkrkLlbb8kODWt_sSoDTQaEApA=.4otC6CrDbr_hcLcfy3w3xw=="
}

# Check protected header
$ echo "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00iLCAia2lkIjogImtpZCIsICJqdGkiOiAibm9uY2UifQ==" | base64 -d
{"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "kid", "jti": "nonce"}
```

A `cek` and `jwe token` will be created for every HTTP request.
