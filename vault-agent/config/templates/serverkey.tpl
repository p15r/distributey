{{ $certData := file "/vault/certs/serverissue.json" | parseJSON }}{{ $certData.private_key }}
