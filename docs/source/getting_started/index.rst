.. _getting-started:

Getting Started
===============

In this guide, we will create a very basic Iroha network, launch it, create a
couple of transactions, and check the data written in the ledger. To keep
things simple, we will use Docker.

.. note:: Ledger is the synonym for a blockchain, and Hyperledger Iroha is
  known also as Distributed Ledger Technology — which in essence is the same
  as "blockchain framework". You can check the rest of terminology used in
  the Glossary section.

Prerequisites
-------------
For this guide, you need a computer running Unix-like system with ``docker``
installed. You can read how to install it on a
`Docker's website <https://www.docker.com/community-edition/>`_.

.. note:: Please note that you can use Iroha without ``docker`` as well. You
  can read about it in other parts of documentation.

Starting Iroha Node
-------------------

.. raw:: html

  <script src="https://asciinema.org/a/z7VkEd0hAfVnwwKcfJCbiRfJT.js" id="asciicast-z7VkEd0hAfVnwwKcfJCbiRfJT" async></script>

Creating a Docker Network
^^^^^^^^^^^^^^^^^^^^^^^^^
To operate, Iroha requires a ``PostgreSQL`` database. Let's start with creating
a Docker network, so containers for Postgres and Iroha can run on the same
virtual network and successfully communicate. In this guide we will call it
``iroha-network``, but you can use any name. In your terminal write following
command:

.. code-block:: shell

  docker network create iroha-network

Starting PostgreSQL Container
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Now we need to run ``PostgreSQL`` in a container, attach it to the network you
have created before, and expose ports for communication:

.. code-block:: shell

  docker run --name some-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=mysecretpassword \
  -p 5432:5432 \
  --network=iroha-network \
  -d postgres:9.5

.. note:: If you already have Postgres running on a host system on default port
  (5432), then you should pick another free port that will be occupied. For
  example, 5433: ``-p 5433:5432 \``

Creating Blockstore
^^^^^^^^^^^^^^^^^^^
Before we run Iroha container, we should create persistent volume to store
files, storing blocks for the chain. It is done via the following command:

.. code-block:: shell

  docker volume create blockstore

Configuring Iroha Network
^^^^^^^^^^^^^^^^^^^^^^^^^

.. note:: To keep things simple, in this guide we will create a network
  containing only one node. To understand how to run several peers, follow
  `this guide. <github.com/hyperledger/iroha/tree/master/deploy/ansible>`_

Now we need to configure our Iroha network. This includes creating a
configuration file, generating keypairs for a users, writing a list of peers
and creating a genesis block. However, we have prepared an example
configuration for this guide, so you can start playing with Iroha faster.
In order to get those files, you need to clone the
`Iroha repository <github.com/hyperledger/iroha>`_ from Github.

.. code-block:: shell

  git clone -b master https://github.com/hyperledger/iroha --depth=1

.. hint:: ``--depth=1`` option allows us to download only latest commit and
  save some time and bandwidth. If you want to get a full commit history, you
  can omit this option.

Starting Iroha Container
^^^^^^^^^^^^^^^^^^^^^^^^
We are ready to launch our Iroha container. Let's do it with the following
command

.. code-block:: shell

  docker run -it --name iroha \
  -p 50051:50051 \
  -v $(pwd)/iroha/example:/opt/iroha_data \
  -v blockstore:/tmp/block_store \
  --network=iroha-network \
  --entrypoint=/bin/bash \
  hyperledger/iroha:latest

Let's look in detail what this command does:

- ``docker run -it --name iroha \`` attaches you to docker container called
  ``iroha``
- with ``$(pwd)/iroha/example:/opt/iroha_data \`` we add a folder containing
  our prepared configuration to a docker container into ``/opt/iroha_data``.
- ``-v blockstore:/tmp/block_store \`` adds a persistent block storage which
  we created before to a container, so our blocks won't be lost after we stop
  the container
- ``--network=iroha-network \`` adds our container to previously created
  ``iroha-network``, so Iroha and Postgres could see each other.
- ``--entrypoint=/bin/bash \`` Because ``hyperledger/iroha`` has
  the custom script which runs after starting the container, we want to
  override it so we can start Iroha Daemon manually.
- ``hyperledger/iroha:latest`` is the image which has the ``master``
  branch.

Launching Iroha Daemon
^^^^^^^^^^^^^^^^^^^^^^
Now you are in the interactive shell of Iroha's container. To actually run
Iroha, we need to launch Iroha daemon – ``irohad``.

.. code-block:: shell

  irohad --config config.docker --genesis_block genesis.block --keypair_name node0

.. Attention:: In the usual situation, you need to provide a config file, generate
  genesis block and keypair. However, as a part of this guide, we provide an
  example configuration for you. Please do not use these settings in a
  production. You can read more about configuration here.

Congratulations! You have an Iroha node up and running! In the next section, we
will test it by sending some transactions.

.. hint:: You can get more information about ``irohad`` and its launch options
  in this section

Interacting with Iroha Network
------------------------------
You can interact with Iroha using various ways. You can use our client libraries
to write code in various programming languages (e.g. Java, Python, Javascript,
Swift) which communicates with Iroha. Alternatively, you can use ``iroha-cli`` –
our command-line tool for interacting with Iroha. As a part of this guide,
let's get familiar with ``iroha-cli``

.. Attention:: Despite that ``iroha-cli`` is arguably the simplest way to start
  working with Iroha, ``iroha-cli`` was engineered very fast and lacks tests,
  so user experience might not be the best. For example, the order of menu items
  can differ from that you see in this guide. In the future, we will deliver a
  better version and appreciate contributions.

.. raw:: html

  <script src="https://asciinema.org/a/6dFA3CWHQOgaYbKfQXtzApDob.js" id="asciicast-6dFA3CWHQOgaYbKfQXtzApDob" async></script>

Open a new terminal (note that Iroha container and ``irohad`` should be up and
running) and attach to an ``iroha`` docker container:

.. code-block:: shell

  docker exec -it iroha /bin/bash

Now you are in the interactive shell of Iroha's container again. We need to
launch ``iroha-cli`` and pass an account name of the desired user. In our example,
the account ``admin`` is already created in a ``test`` domain. Let's use this
account to work with Iroha.

.. code-block:: shell

  iroha-cli -account_name admin@test

.. note:: Full account name has a ``@`` symbol between name and domain. Note
  that the keypair has the same name.

Creating the First Transaction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can see the interface of ``iroha-cli`` now. Let's create a new asset, add
some asset to the admin account and transfer it to other account. To achieve
this, please choose option ``1. New transaction (tx)`` by writing ``tx`` or
``1`` to a console.

Now you can see a list of available commands. Let's try creating a new asset.
Select ``14. Create Asset (crt_ast)``. Now enter a name for your asset, for
example ``coolcoin``. Next, enter a Domain ID. In our example we already have a
domain ``test``, so let's use it. Then we need to enter an asset precision
– the amount of numbers in a fractional part. Let's set precision to ``2``.

Congratulations, you have created your first command and added it to a
transaction! You can either send it to Iroha or add some more commands
``1. Add one more command to the transaction (add)``. Let's add more commands,
so we can do everything in one shot. Type ``add``.

Now try adding some ``coolcoins`` to our account. Select ``16. Add Asset
Quantity (add_ast_qty)``, enter asset ID – ``coolcoin#test``, integer part and
precision. For example, to add 200.50 ``coolcoins``, we need to enter integer
part as ``20050`` and precision as ``2``, so it becomes ``200.50``.

.. note:: Full asset name has a ``#`` symbol between name and domain.

Let's transfer 100.50 ``coolcoins`` from ``admin@test`` to ``test@test``
by adding one more command and choosing ``5. Transfer Assets (tran_ast)``.
Enter Source Account and Destination Account, in our case ``admin@test`` and
``test@test``, Asset ID (``coolcoin#test``), integer part and precision
(``10050`` and ``2`` accordingly).

Now we need to send our transaction to Iroha peer (``2. Send to Iroha peer
(send)``). Enter peer address (in our case ``localhost``) and port (``50051``).
Congratulations, your transaction is submitted and you can see your transaction
hash. You can use it to check transaction's status.

Go back to a terminal where ``irohad`` is running. You can see logs of your
transaction.

Congratulations! You have submitted your first transaction to Iroha.

Creating the First Query
^^^^^^^^^^^^^^^^^^^^^^^^

Now let's check if ``coolcoins`` were successfully transferred from
``admin@test`` to ``test@test``. Choose ``2. New query
(qry)``. ``8. Get Account's Assets (get_acc_ast)`` can help you to check if
``test@test`` now has ``coolcoin``. Form a query in a similar way you did with
commands you did with commands and ``1. Send to Iroha peer (send)``. Now you
can see information about how many ``coolcoin`` does ``test@test`` have.
It will look similar to this:

.. code::

  [2018-03-21 12:33:23.179275525][th:36][info] QueryResponseHandler [Account Assets]
  [2018-03-21 12:33:23.179329199][th:36][info] QueryResponseHandler -Account Id:- test@test
  [2018-03-21 12:33:23.179338394][th:36][info] QueryResponseHandler -Asset Id- coolcoin#test
  [2018-03-21 12:33:23.179387969][th:36][info] QueryResponseHandler -Balance- 100.50``

Congratulations! You have submitted your first query to Iroha and got a
response!

.. hint:: To get information about all available commands and queries
  please check our API section.

Being Badass
^^^^^^^^^^^^

Let's try being badass and cheat Iroha. For example, let's transfer more
``coolcoins`` than ``admin@test`` has. Try to transfer 100000.00 ``coolcoins``
from ``admin@test`` to ``test@test``. Again, proceed to ``1. New transaction
(tx)``, ``5. Transfer Assets (tran_ast)``, enter Source Account and Destination
Account, in our case ``admin@test`` and ``test@test``, Asset ID
(``coolcoin#test``), integer part and precision (``10000000`` and ``2``
accordingly). Send a transaction to Iroha peer as you did before. Well, it says

.. code::

  [2018-03-21 12:58:40.791297963][th:520][info] TransactionResponseHandler Transaction successfully sent
  Congratulation, your transaction was accepted for processing.
  Its hash is fc1c23f2de1b6fccbfe1166805e31697118b57d7bb5b1f583f2d96e78f60c241

`Your transaction was accepted for processing`. Does it mean that we
had successfully cheated Iroha? Let's try to see transaction's status. Choose
``3. New transaction status request (st)`` and enter transaction's hash which
you can get in the console after the previous command. Let's send it to Iroha.
It replies with:

.. code::

  Transaction has not passed stateful validation.

Apparently no. Our transaction was not accepted because it did not pass
stateful validation and ``coolcoins`` were not transferred. You can check
the status of ``admin@test`` and ``test@test`` with queries to be sure
(like we did earlier).
