.. _deploy_troubles:

=====================
Dealing with troubles
=====================

—"Please, help me, because I…"

Do not have Iroha daemon binary
-------------------------------

You can build Iroha daemon binary from sources. You can get binaries `here <https://github.com/hyperledger/iroha/releases>`__

Do not have a config file
-------------------------

Check how to create a configuration file by following this `link <../configure/index.html>`__

Do not have a genesis block
---------------------------

Create genesis block by generating it via `iroha-cli` or manually, using the `example <https://github.com/hyperledger/iroha/blob/master/example/genesis.block>`__ and checking out `permissions <../develop/api/permissions.html>`__

Do not have a keypair for a peer
--------------------------------

In order to create a keypair for an account or a peer, use iroha-cli binary by passing the name of the peer with `--new_account` option.
For example:

.. code-block:: shell

    ./iroha-cli --account_name newuser@test --new_account
