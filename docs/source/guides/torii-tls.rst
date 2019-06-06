Configure TLS for client-peer communication (torii)
===================================================
By default, client-peer communication is not encrypted.
To enable it, you need to:

1. `Generate <Generating keys>`_ a key/certificate pair for each peer
2. Distribute the certificate to all clients
3. `Configure <Configuring irohad>`_ irohad to use these keys
4. [Re]start irohad


Generating keys
~~~~~~~~~~~~~~~

Keys must be presented in PEM format. To generate them you can use ``openssl``:

```bash
$ openssl genpkey -algorithm <desired algorithm> -out server.key
$ openssl req -new -key server.key -x509 -out server.crt
```

Fields in the certificate don't really matter except for the Common Name (CN),
it would be checked against the client's address, and TLS handshake will fail
if they do not match (e.g. if you connect to 12.34.56.78:50051, then irohad
at 12.34.56.78 would need to have 12.34.56.78 in common name of the certificate)

Configuring irohad
~~~~~~~~~~~~~~~~~~

To configure iroha to use your keys, you need to modify ``torii_tls_port`` and
``torii_tls_keypair`` config parameters.

``torii_tls_port`` - set this to any port you would like (but usually you
would want 50052)

``torii_tls_keypair`` - set this to full path to the key/certificate pair,
so if you have a key at ``/path/to/server.key`` and a certificate at
``/path/to/server.crt``, you need to specify 
``torii_tls_keypair=/path/to/server``
