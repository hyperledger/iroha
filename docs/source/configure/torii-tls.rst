Configure TLS for client-peer communication (torii)
===================================================
By default, client-peer communication is not encrypted.
To enable it, you need to:

1. `Generate <#generating-keys>`_ a key/certificate pair for each peer
2. Distribute the certificate to all clients
3. `Configure <#configuring-irohad>`_ irohad to use these keys
4. [Re]start irohad


Generating keys
~~~~~~~~~~~~~~~

Keys must be presented in PEM format. To generate them you can use ``openssl``:

.. code-block:: sh

    $ openssl genpkey -algorithm rsa -out server.key
    $ openssl req -new -key server.key -x509 -out server.crt

You can use any algorithm you want instead of ``rsa``, as long as your
``openssl`` supports it.
To find out which are supported, you can use

.. code-block:: sh

    $ openssl list-public-key-algorithms

If you need to use plain IP addresses to connect to the node, you need to
specify ``subjectAltName`` in your server certificate, for that you need to add
a ``subjectAltName`` directive to ``v3_ca`` section of your openssl config
before generating the certificate.
For example, for the default installation, ``/etc/ssl/openssl.cnf``:

.. code-block:: text

    [ v3_ca ]
    subjectAltName=IP:12.34.56.78

Fields in the certificate don't really matter except for the Common Name (CN),
it would be checked against the client's hostname, and TLS handshake will fail
if they do not match (e.g. if you connect to example.com:50051, then irohad at
example.com would need to have example.com in common name of the certificate).

Configuring irohad
~~~~~~~~~~~~~~~~~~

To configure iroha to use your keys, you need to modify the ``torii_tls_params``
config parameter.

It should look like the following block:

.. code-block:: javascript

    "torii_tls_params": {
        "port": 55552,
        "key_pair_path": "/path/to/server"
    }

``port`` - set this to any port you would like (but usually you
would want 55552)

``key_pair_path`` - set this to full path to the key/certificate pair,
such that if you have a key at ``/path/to/server.key`` and a certificate at
``/path/to/server.crt``, you need to specify
``torii_tls_keypair=/path/to/server``

.. note:: In `the examples directory <https://github.com/hyperledger/iroha/tree/main/example/torii_tls>`_ there are sample certificates, but to enable TLS you need to have a new certificate for your server (the sample will not work).
