# Local TLS test material

The `local_tls_pair` pytest fixture in `tests/conftest.py` creates a fresh self-signed certificate and private key inside `tmp_path` for each test. The loopback HTTPS rejection test verifies that certificate validation fails before an HTTP request reaches the server. No private-key material is committed.
