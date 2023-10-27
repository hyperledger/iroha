=======================
Running single instance
=======================

Generally, people want to run Iroha locally in order to try out the API and explore the capabilities.
This can be done in local or container environment (Docker).
We will explore both possible cases,
but in order to simplify peer components deployment, *it is advised to have Docker installed on your machine*.

Local environment
-----------------

By local environment, it is meant to have daemon process and Postgres deployed without any containers.
This might be helpful in cases when messing up with Docker is not preferred — generally a quick exploration of the features.

Run postgres server
"""""""""""""""""""

In order to run postgres server locally, you should check postgres `website <https://www.postgresql.org/docs/current/static/server-start.html>`__ and follow their description.
Generally, postgres server runs automatically when the system starts, but this should be checked in the configuration of the system.

Postgres database server could be initialized and started manually without usual system integration:

.. code-block::shell

   initdb ~/iroha/nodeX_db/
   ## Start server in background, logs will appear in current console
   postgres -D ~/iroha/nodaX_db/ -p5433 &
   createuser -s iroha_user -p5433

Selected port ``5433`` (default is 5432) and database user ``iroha_user`` are used by irohad to connect to database. 
(see `Configuration parameters <../configure/index.html>`_ for more reference). Maintenance database ``postgres`` is created by default, but if for some reason another name required, create it:

.. code-block::shell

   createdb iroha_mainteance -p5433


Run iroha daemon (irohad)
"""""""""""""""""""""""""

There is a list of preconditions which you should meet before proceeding:

 * Postgres server is up and running
 * `irohad` Iroha daemon binary is built and accessible in your system
 * The genesis block and configuration files were created
 * Config file uses valid postgres connection settings
 * A keypair for the peer is generated
 * This is the first time you run the Iroha on this peer and you want to create new chain

.. Hint:: Have you got something that is not the same as in the list of assumptions? Please, refer to the section :ref:`deploy_troubles`.

In case of valid assumptions, the only thing that remains is to launch the daemon process with following parameters:

+---------------+-----------------------------------------------------------------+
| Parameter     | Meaning                                                         |
+---------------+-----------------------------------------------------------------+
| config        | configuration file, containing postgres connection and values   |
|               | to tune the system                                              |
+---------------+-----------------------------------------------------------------+
| genesis_block | initial block in the ledger                                     |
+---------------+-----------------------------------------------------------------+
| keypair_name  | private and public key file names without file extension,       |
|               | used by peer to sign the blocks                                 |
+---------------+-----------------------------------------------------------------+

.. Attention:: Specifying a new genesis block using `--genesis_block` with blocks already present in ledger requires `--overwrite_ledger` flag to be set. The daemon will fail otherwise.

An example of shell command, running Iroha daemon is

.. code-block:: shell

    irohad --config example/config.sample --genesis_block example/genesis.block --keypair_name example/node0

.. Note:: if you are running Iroha built with `HL Ursa support <../integrations/index.html#hyperledger-ursa>`_ please get the example keys and genesis block in `example/ursa-keys/`

.. Attention:: If you have stopped the daemon and want to use existing chain — you should not pass the genesis block parameter.


Docker
------

In order to run Iroha peer as a single instance in Docker, you should pull the image for Iroha first:

.. code-block:: shell

    docker pull hyperledger/iroha:latest

.. Hint:: Use *latest* tag for latest stable release, and *develop* for latest development version

Then, you have to create an environment for the image to run without problems:

Create docker network
"""""""""""""""""""""

Containers for Postgres and Iroha should run in the same virtual network, in order to be available to each other.
Create a network, by typing following command (you can use any name for the network, but in the example, we use *iroha-network* name):

.. code-block:: shell

    docker network create iroha-network

Run Postgresql in a container
"""""""""""""""""""""""""""""

Similarly, run postgres server, attaching it to the network you have created before, and exposing ports for communication:

.. code-block:: shell

    docker run --name some-postgres \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=mysecretpassword \
    -p 5432:5432 \
    --network=iroha-network \
    -d postgres:9.5

Create volume for block storage
"""""""""""""""""""""""""""""""

Before we run iroha daemon in the container, we should create persistent volume to store files, storing blocks for the chain.
It is done via the following command:

.. code-block:: shell

    docker volume create blockstore

Running iroha daemon in docker container
""""""""""""""""""""""""""""""""""""""""

There is a list of assumptions which you should review before proceeding:
 * Postgres server is running on the same docker network
 * There is a folder, containing config file and keypair for a single node
 * This is the first time you run the Iroha on this peer and you want to create new chain

If they are met, you can move forward with the following command:

.. code-block:: shell

    docker run --name iroha \
    # External port
    -p 50051:50051 \
    # Folder with configuration files
    -v ~/Developer/iroha/example:/opt/iroha_data \
    # Blockstore volume
    -v blockstore:/tmp/block_store \
    # Postgres settings
    -e POSTGRES_HOST='some-postgres' \
    -e POSTGRES_PORT='5432' \
    -e POSTGRES_PASSWORD='mysecretpassword' \
    -e POSTGRES_USER='postgres' \
    # Node keypair name
    -e KEY='node0' \
    # Docker network name
    --network=iroha-network \
    hyperledger/iroha:latest
