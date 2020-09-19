# Prerequisites 📚
- `docker-compose` (v3.7+)
- TLS cert & key for reverse proxy: `Nginx` is used as reverse proxy. Create certificate that matches (`CN`) your desired URL of the HYOK Wrapper. Most key consumers, such as Salesforce, require valid certificates, signed by an official root CA.
