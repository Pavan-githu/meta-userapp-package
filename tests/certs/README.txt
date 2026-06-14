Place test client certificates here for mTLS tests (TC-19 / TC-20):

  tests/certs/client.crt   — client certificate signed by the Root CA
  tests/certs/client.key   — corresponding private key

Generate with:
  openssl genrsa -out client.key 4096
  openssl req -new -key client.key -out client.csr -subj "/CN=cloudflared-client"
  openssl x509 -req -in client.csr -CA rootca.crt -CAkey rootca.key \
          -CAcreateserial -out client.crt -days 365

These files are gitignored (contain key material).
