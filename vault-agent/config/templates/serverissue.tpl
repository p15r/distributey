{{ with secret "HYOK-Wrapper/issue/server" "common_name=nginx-server.hyok.vt.ch" "ttl=26280h" }}
{{ .Data | toJSONPretty }}{{ end }}