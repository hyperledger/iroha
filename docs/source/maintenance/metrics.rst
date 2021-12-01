=======
Metrics
=======

To conveniently and thoroughly monitor the performance of the network, you can now use metrics.
It is numeric data collected over time about your Iroha network.
You can then analyse the data to make your project even more efficient!

How to use metrics?
===================

To use metrics, you need to add it to your `Iroha configuration <../configure/index.html#deployment-specific-parameters>`_ and use Iroha version that is newer than 1.2.1.

.. note:: If you are running Iroha in Docker, to access metrics from outside the countainer you will need to: 1) In `config <../configure/index.html>`_ -- set up ``"metrics":0.0.0.0:PORT``; 2) Expose corresponding port in Docker while executing ``run ... -pPORT:PORT ...``


Then, you can simply use the ip address to access the data from the running Iroha instance.

Here is an example:

.. code-block:: shell

  > curl http://127.0.0.1:8080/metrics

will give you results like: 

.. code-block:: shell

  # HELP blocks_height Total number of blocks in chain
  # TYPE blocks_height gauge
  blocks_height 135543
  # HELP peers_number Total number peers to send transactions and request proposals
  # TYPE peers_number gauge
  peers_number 7
  # HELP number_of_domains Total number of domains in WSV
  # TYPE number_of_domains gauge
  number_of_domains 14
  # HELP total_number_of_transactions Total number of transactions in blockchain
  # TYPE total_number_of_transactions gauge
  total_number_of_transactions 216499
  # HELP number_of_signatures_in_last_block Number of signatures in last block
  # TYPE number_of_signatures_in_last_block gauge
  number_of_signatures_in_last_block 5