{{ with secret "HYOK-Wrapper/issue/client" "common_name=nginx-client.hyok.vt.ch" "ttl=26280h" }}
{{ .Data.certificate }}{{ end }}