.. _inter-peer-tls:

TLS for Inter-peer communication
================================

Iroha can encrypt all traffic between nodes in a network.
For that you would need to generate a key/certificate pair for each peer in the
network (see :ref:`torii TLS configuration <torii-tls>`).

Certificates of each peer are parameters to the ``AddPeer`` command