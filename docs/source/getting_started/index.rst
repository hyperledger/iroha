.. _getting-started:

=================
Quick Start Guide
=================

In this guide, we will create a very basic Iroha network, launch it, create a
couple of transactions, and check the data written in the ledger.
To keep things simple, we will use Docker.

.. note:: Ledger is the synonym for a blockchain, and Hyperledger Iroha is known
  also as Distributed Ledger Technology framework — which in essence is the same as "blockchain framework".
  You can check the rest of terminology used in the :ref:`core-concepts` section.

Prerequisites
-------------
For this guide, you need a machine with ``Docker`` installed.
You can read how to install it on a `Docker's website <https://docs.docker.com/get-docker/>`_.

.. note:: Of course you can build Iroha from scratch, modify its code and launch a customized node!
  If you are curious how to do that — you can check :ref:`build-guide` section.
  In this guide we will use a standard distribution of Iroha available as a docker image.

Starting Iroha Node
-------------------

.. raw:: html

  <script id="asciicast-345137" src="https://asciinema.org/a/345137.js" async></script>

Creating a Docker Network
^^^^^^^^^^^^^^^^^^^^^^^^^
To operate, Iroha requires a ``PostgreSQL`` database or ``RocksDB``.
If you prefer ``PostgreSQL``, you will need a container running it alongside Iroha.


Let's start with creating a Docker network, so containers for Postgres and
Iroha can run on the same virtual network and successfully communicate.
In this guide we will call it ``iroha-network``, but you can use any name.
In your terminal write following command:

.. code-block:: shell

  docker network create iroha-network

Starting PostgreSQL Container
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note:: You do not need to start this container if your plan is to use Iroha with RocksDB and not PostgreSQL. Just skip to the next step. 

Now we need to run ``PostgreSQL`` in a container, attach it to the network
you have created before, and expose ports for communication:

.. code-block:: shell

  docker run --name some-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=mysecretpassword \
  -p 5432:5432 \
  --network=iroha-network \
  -d postgres:9.5 \
  -c 'max_prepared_transactions=100'

.. note:: If you already have Postgres running on a host system on default port (5432),
  then you should pick another free port that will be occupied.
  For example, 5433: ``-p 5433:5432``

Creating Blockstore
^^^^^^^^^^^^^^^^^^^
Before we run Iroha container, we may create a persistent volume to store files, storing blocks for the chain.
It is done via the following command:

.. code-block:: shell

  docker volume create blockstore

Preparing the configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note:: To keep things simple, in this guide we will create a network containing only a single node.
  To understand how to run several peers, follow :ref:`deploy-guide`

Now we need to configure our Iroha network.
This includes creating a configuration file, generating keypairs for a users,
writing a list of peers and creating a genesis block.

Don't be scared away — we have prepared an example configuration for this guide,
so you can start testing Iroha node now.
In order to get those files, you need to clone the `Iroha repository <https://github.com/hyperledger/iroha>`_
from Github or copy them manually (cloning is faster, though).

.. code-block:: shell

  git clone -b main https://github.com/hyperledger/iroha --depth=1

.. hint:: ``--depth=1`` option allows us to download only the latest commit and
  save some time and bandwidth. If you want to get a full commit history, you
  can omit this option.

There is a guide on how to set up the parameters and tune them with respect to your
environment and load expectations: :ref:`configuration`.
We don't need to do this at the moment.

Starting Iroha Container
^^^^^^^^^^^^^^^^^^^^^^^^
We are almost ready to launch our Iroha container.
You just need to know the path to configuration files (from the step above).

Let's start Iroha node in Docker container with the following command:

.. code-block:: shell

  docker run --name iroha \
  -d \
  -p 50051:50051 \
  -v $(pwd)/iroha/example:/opt/iroha_data \
  -v blockstore:/tmp/block_store \
  --network=iroha-network \
  -e KEY='node0' \
  hyperledger/iroha:latest

.. note:: If you are using Iroha with RocksDB, please add ``--entrypoint irohad`` to these parameters, to skip the PostgreSQL container check.
.. note:: To use `metrics <../maintenance/metrics.html>`_ with Docker please also set up the port ``-p7001:7001`` and edit the ``config.docker`` file with ``0.0.0.0:7001``.

If you started the node successfully you would see the container id in the same console where you started the container.

Let's look in details what this command does:

- ``docker run --name iroha \`` creates a container ``iroha``
- ``-d \`` runs container in the background
- ``-p 50051:50051 \`` exposes a port for communication with a client (we will use this later)
- ``-v YOUR_PATH_TO_CONF_FILES:/opt/iroha_data \`` is how we pass our configuration files to
  docker container. The example directory is indicated in the code block above.
- ``-v blockstore:/tmp/block_store \`` adds persistent block storage (Docker volume) to a container,
  so that the blocks aren't lost after we stop the container
- ``--network=iroha-network \`` adds our container to previously created ``iroha-network``
  for communication with PostgreSQL server
- ``-e KEY='node0' \`` - here please indicate a key name that will identify the node allowing it to confirm operations.
  The keys should be placed in the directory with configuration files mentioned above.
- ``hyperledger/iroha:latest`` is a reference to the image pointing to the
  latest `release <https://github.com/hyperledger/iroha/releases>`__

You can check the logs by running ``docker logs iroha``.

You can try using one of sample guides in order to send some transactions to Iroha and query its state.

Try other guides
----------------

.. toctree::
      :maxdepth: 2

      cli-guide.rst
      python-guide.rst
