.. _inter-peer-tls:

TLS for Inter-peer communication
================================

Iroha can encrypt all traffic between nodes in a network.
For that you would need to generate a key/certificate pair for each peer in the
network (see :ref:`torii TLS configuration <torii-tls>`).

Individual peer certificates must include critical subject alternative name extension (SAN) of type OtherName
with object identifier 1.3.101.112, corresponding to ED25519 public key, and with the value of the peer key
as ASN1 integer.

.. codeblock::
  :linenos:

  SEQUENCE (1 elem) extensions
    SEQUENCE (3 elem)
      OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
      BOOLEAN true critical
      OCTET STRING (1 elem)
        SEQUENCE (1 elem)
          [0] (2 elem)
            OBJECT IDENTIFIER 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
            [0] (1 elem)
              INTEGER (256 bit) 85878210670785... public key

We advise you to use our python script ``utils/p2p_cert_helper.py`` to generate the SAN from a public key:

.. codeblock::
   utils/p2p_cert_helper.py
         --iroha-pubkey public_key_hex
         --create-and-store-tls-key path/to/output/private_tls_key
         -O path/to/output/certificate
         gen_self_signed_cert

or

.. codeblock::
   utils/p2p_cert_helper.py
         --iroha-pubkey-path example/node0.pub
         --tls-key-path path/to/private_tls_key
         -O path/to/output/certificate_request
         gen_req

   utils/p2p_cert_helper.py
         --req path/to/certificate_request
         --cert path/to/ca_certificate
         --tls-key-path path/to/ca_private_tls_key
         -O path/to/output/certificate
         sign_req

You can also see which iroha keys does a certificate autorize (as for the moment of writing this, `openssl x509` could not display it):

.. codeblock::
   utils/p2p_cert_helper.py --cert path/to/certificate extract_keys
   utils/p2p_cert_helper.py --req path/to/certificate_request extract_keys

All the options for `utils/p2p_cert_helper.py` can be shown by specifying `--help` flag.

All certificates and keys are stored in PEM format.

In case you want to use self-signed certificates verified by ledger, add them to ``AddPeer`` command.
