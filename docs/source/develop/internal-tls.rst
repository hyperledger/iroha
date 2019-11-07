.. _inter-peer-tls:

TLS for Inter-peer communication
================================

Iroha can encrypt all traffic between nodes in a network.
For that you would need to generate a key/certificate pair for each peer in the
network (see :ref:`torii TLS configuration <torii-tls>`).

Individual peer certificates must include critical subject alternative name extension (SAN) with two values of type DNS:

.. codeblock::
  :linenos:

   iroha
   iroha-node-public-key.<key_chunk>.<key_chunk>.<...>.<key_chunk>

Here, ``<key_chunk>`` is a part of node public key (the one you use in ``AddPeer`` command).
We advise you to use our python script ``utils/p2p_cert_helper.py`` to generate the SAN from a public key:

.. codeblock::
   utils/p2p_cert_helper.py --iroha-pubkey public_key_hex gen_san

or

.. codeblock::
   utils/p2p_cert_helper.py --iroha-pubkey-path example/node0.pub gen_san

It can also make a certificate request for you if you use ``gen_req`` command. In this case you must also provide the TLS private key file path.

But you can also make it manually.
For that, convert your public key into a single hex string (no line breaks and headers/footers) and, starting from the beginning, insert a dot after every 63 character block.
Then prepend the string with ``iroha-node-public-key.``.
This is required to meet the RFC for DNS name.
This algorithm can transform a public key to fully legal domain name and vice-versa without ambiguities and thus can be used for key certification.

All certificates and keys are stored in PEM format.
In case you want to use self-signed certificates verified by ledger, add them to ``AddPeer`` command.
