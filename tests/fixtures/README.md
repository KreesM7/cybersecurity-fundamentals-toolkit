# Local TLS test material

`local-cert.txt` and `local-key.txt` are a generated, self-signed certificate and its openly published key for a temporary loopback fixture. They are deliberately untrusted and verify that HTTPS validation rejects them before an HTTP request reaches the fixture. They are not application credentials and must never be used for a deployed server.
