{{ $certData := file "/vault/certs/serverissue.json" | parseJSON }}{{ $certData.certificate }}
