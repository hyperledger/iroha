.. _configuration:

=========
Configure
=========

.. toctree::
      :maxdepth: 1

      torii-tls.rst
      db.rst

In this section we will understand how to configure Iroha.
Some configuration parameters must be the same in all the nodes (they are marked with \*) and some can differ.
Let's take a look
at ``example/config.sample``

.. note:: Starting with v1.2 ``irohad`` can also be configured via environment variables, not only via config file.

We will start with looking at config file and then look at how Iroha can be configured with `environment parameters <#environment-variables>`_.

.. literalinclude:: ../../../example/config.sample
   :language: json


As you can see, configuration file is a valid ``json`` structure.
Let's go line-by-line and understand what every parameter means in configuration file format.

Deployment-specific parameters
==============================

- ``block_store_path`` (optional) sets path to the folder where blocks are stored. If this parameter is not specified, blocks will be stored in the database.
- ``torii_port`` sets the port for external communications. Queries and
  transactions are sent here.
- ``internal_port`` sets the port for internal communications: ordering
  service, consensus and block loader.
- ``database`` (optional) is used to set the database configuration (see below)
- ``pg_opt`` (optional) is a **deprecated** way of setting credentials of PostgreSQL:
  hostname, port, username, password and database name.
  All data except the database name are mandatory.
  If database name is not provided, the default one gets used, which is ``iroha_default``.
- ``log`` is an optional parameter controlling log output verbosity and format
  (see below).
- ``utility_service`` (optional) endpoint for maintenance tasks.
  If present, must include ``ip`` address and ``port`` to bind to.
  See `shepherd docs <../maintenance/shepherd.html>`_ for an example usage of maintenance endpoint.
- ``metrics`` (optional) endpoint to monitor Iroha's metrics. Prometheus HTTP server listens on this endpoint.
  If present, must correspond format "[addr]:<port>" and could be for example "127.0.0.1:8080", "9090", or ":1234".
  Wrong values implicitly disables Prometheus metrics server. There are also cmdline options ```--metrics_port`` and
  ``--metrics_addr`` to override this parameter.
- ``healthcheck_port`` (optional) endpoint for Iroha healthcheck. Sending a request to this endpoint in the form of ``http://<host>:<healthcheck_port>/healthcheck`` will return you information about the status of the node: current memory consumption (``memory_consumption``), current number of blocks (``last_block_round``), current count of reject rounds (``last_reject_round``), if the node is syncing information with a remote node at the moment (``is_syncing``), if the node is currently up (``status``). 

There is also an optional ``torii_tls_params`` parameter, which could be included
in the config to enable TLS support for client communication.

There, ``port`` is the TCP port where the TLS server will be bound, and
``key_pair_path`` is the path to the keypair in a format such that appending
``.crt`` to it would be the path to the PEM-encoded certificate, and appending
``.key`` would be the path to the PEM-encoded private key for this certificate
(e.g. if ``key_pair_path`` is ``"/path/to/the/keypair"`` iroha would look for
certificate located at ``"/path/to/the/keypair.crt"`` and key located at
``"/path/to/the/keypair.key"``)

.. warning::
   Configuration field ``pg_opt`` is deprecated, please use ``database`` section!

   The ``database`` section overrides ``pg_opt`` when both are provided in configuration.

   Both ``pg_opt`` and ``database`` fields are optional, but at least one must be specified.

The ``database`` section fields:

- ``host`` the host to use for PostgreSQL connection
- ``port`` the port to use for PostgreSQL connection
- ``user`` the user to use for PostgreSQL connection
- ``password`` the password to use for PostgreSQL connection
- ``working database`` is the name of database that will be used to store the world state view and optionally blocks.
- ``maintenance database`` is the name of databse that will be used to maintain the working database.
  For example, when iroha needs to create or drop its working database, it must use another database to connect to PostgreSQL.

Environment-specific parameters
===============================

- ``max_proposal_size`` \* is the maximum amount of transactions that can be in
  one proposal, and as a result in a single block as well. So, by changing this
  value you define the size of potential block. For a starter you can stick to
  ``10``. However, we recommend to increase this number if you have a lot of
  transactions per second.

    **This parameter affects performance.** Increase this parameter, if your network has a big number of transactions going. If you increase ``max_proposal_size`` due to an inreased throughput, you can increase it independently. By increasing this parameter you can improve the performance but note that at some point increasing this value can lead to degradation of the performance.

- ``vote_delay`` \* is a waiting time in milliseconds before sending vote to the
  next peer. Optimal value depends heavily on the amount of Iroha peers in the
  network (higher amount of nodes requires longer ``vote_delay``). ** We strongly recommend
  to set it to at least one second - otherwise when some of the peers are not easily reachable, the chain of blocks will grow very slowly or even stop growing.**

    **This parameter only affects consensus mechanism.** If your network is fast - you are good and this parameter does not effect your network much. But if your network is on a slower side, increase it to give more time for the peers to respond.

- ``mst_enable`` enables or disables multisignature transaction network
  transport in Iroha.
  Note that MST engine always works for any peer even when the flag is set to
  ``false``.
  The flag only allows sharing information about MST transactions among the
  peers.

- ``mst_expiration_time`` is an optional parameter specifying the time period
  in which a not fully signed transaction (or a batch) is considered expired
  (in minutes).
  The default value is 1440.

- ``proposal_creation_timeout`` (previously - ``max_rounds_delay``)\* is an optional parameter specifying the maximum delay
  between two consensus rounds (in milliseconds).
  The default value is 3000.
  When Iroha is idle, it gradually increases the delay to reduce CPU, network
  and logging load.
  However too long delay may be unwanted when first transactions arrive after a
  long idle time.
  This parameter allows users to find an optimal value in a tradeoff between
  resource consumption and the delay of getting back to work after an idle

    **This parameter affects resource consumption.** When you can expect Iroha to stay idle for longer periods of time and would like to save some resources, increase this value - it will make Iroha check for new transactions more rarely. NB: the first transaction after idle period might be a little delayed due to that. Second and further blocks will be processed quicker.

- ``stale_stream_max_rounds`` is an optional parameter specifying the maximum
  amount of rounds to keep an open status stream while no status update is
  reported.
  The default value is 2.
  Increasing this value reduces the amount of times a client must reconnect to
  track a transaction if for some reason it is not updated with new rounds.
  However large values increase the average number of connected clients during
  each round.

    It is recommended to limit this parameter to make sure the node is not overloaded with streams.

- ``initial_peers`` is an optional parameter specifying list of peers a node
  will use after startup instead of peers from genesis block.
  It could be useful when you add a new node to the network where the most of
  initial peers may become malicious.
  Peers list should be provided as a JSON array:

.. code-block:: javascript

  "initial_peers": [
    {
      "address": "127.0.0.1:10001",
      "public_key": "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"
    }
  ]

- ``max_past_created_hours``: optional parameter specifying how many hours in the past since current time (measured on the peer) can the transaction's `created_time` be set. The default value is `"24"` hours. This value must be the same on all peers, otherwise it can silently cause the network to stop producing blocks.

Good Practice Example
---------------------

With even distribution we received quite good results - with 300k transactions sent in 5 minutes.
Commit took from 2 seconds to 2 minutes.
**Please note that results always depend on number of peers in your network, its speed and parameters of the hosts on which the peers run.**

Here is the configuration we used:

.. code-block:: javascript

  "max_proposal_size" : 10000,
  "vote_delay" : 1000,
  "mst_enable" : true,
  "mst_expiration_time": 1440,
  "proposal_creation_timeout": 500,
  "stale_stream_max_rounds": 100000


Environment variables
=====================

Another way to configure Iroha is by using environment variables.
Configuration file and environment variables can be combined.
**The parameters specified in the configuration file, if present, will override the ones that are set up through environment.**

Here are some examples of how parameters will look like in

Unix
----

.. code-block:: bash

  export IROHA_BLOCK_STORE_PATH=/tmp/block_store/
  export IROHA_TORII_PORT=50051
  export IROHA_INTERNAL_PORT=10001
  export IROHA_PG_OPT="host=172.19.0.2 port=5432 user=iroha password=helloworld"
  export IROHA_MAX_PROPOSAL_SIZE=10
  export IROHA_VOTE_DELAY=5000
  export IROHA_MST_ENABLE=false
  export IROHA_MST_EXPIRATION_TIME=1440
  export IROHA_PROPOSAL_CREATION_TIMEOUT=3000
  export IROHA_CRYPTO_PROVIDERS_0_KEY=p1
  export IROHA_CRYPTO_PROVIDERS_0_CRYPTO_TYPE=ed25519_sha3_256
  export IROHA_CRYPTO_PROVIDERS_0_PRIVATE_KEY=cc5013e43918bd0e5c4d800416c88bed77892ff077929162bb03ead40a745e88
  export IROHA_CRYPTO_PROVIDERS_0_TYPE=default
  export IROHA_CRYPTO_SIGNER=p1

Windows
-------

.. code-block:: bat

  setx IROHA_BLOCK_STORE_PATH C:\block_store
  setx IROHA_TORII_PORT 50051
  setx IROHA_INTERNAL_PORT 10001

PowerShell
----------

.. code-block:: bash

  $Env:IROHA_BLOCK_STORE_PATH="C:\block_store"
  $Env:IROHA_TORII_PORT="50051"
  $Env:IROHA_INTERNAL_PORT="10001"

Parameter names
---------------

As you can see, the parameter names are not the same as in the configuration file.

They are formed from the config structure, fixed label IROHA is added to the beginning and everything is uppercased and joined with _.
Let us look a bit closer at how they are structured:

**With simple string values**

In configuration file:

.. code-block:: javascript

  "block_store_path": "/tmp/block_store/"

In environment variables:

.. code-block:: bash

  IROHA_BLOCK_STORE_PATH=/tmp/block_store/


**With arrays**

Arrays are indexed starting with 0 and should be in direct order without skipping any numbers:

In configuration file:

.. code-block:: javascript

  "initial_peers": [
    {
      "address": "127.0.0.1:10001",
      "public_key": "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"
    },
    {
      "address": "127.0.0.1:10002",
      "public_key": "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308920"
    }
  ]

In environment variables:

.. code-block:: bash

  IROHA_INITIAL_PEERS_0_ADDRESS=127.0.0.1:10001
  IROHA_INITIAL_PEERS_0_PUBLIC_KEY=bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929
  IROHA_INITIAL_PEERS_1_ADDRESS=127.0.0.1:10002
  IROHA_INITIAL_PEERS_1_PUBLIC_KEY=bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308920

**Dictionaries with user-defined keys**

User-provided dictionary keys are a bit trickier: the key and the value are set in separate variables.
They can be illustrated on the example of configuring cryptography providers:

Crypto providers
================

Currently, HL Iroha supports one type of provider called ``default`` — it includes built-in crypto providers such as HL Iroha crypto library (with crypto type ``ed25519_sha3_256``) and HL Ursa library of which Iroha currently supports crypto type ``ed25519_sha2_256``.

Both of them take only the ``crypto_type`` and ``private_key`` as parameters.

.. note::  We are working on adding other types, including ``hsm`` — for hardware security modules — they will have a different set of parameters which will be added here after the release.

Configuring crypto providers
----------------------------

To configure currently available crypto providers, you need to define the providers that might be used on the peer (see ``p1`` and ``p2``) and then choose the ``signer``, that will be used to sign messages on this node:

In configuration file:

.. code-block:: javascript

  "crypto": {
    "providers": {
      "p1": {
        "crypto_type": "ed25519_sha3_256",
        "private_key": "cc5013e43918bd0e5c4d800416c88bed77892ff077929162bb03ead40a745e88",
        "type": "default"
      },
      "p2": {
        "crypto_type": "ed25519_sha2_256",
        "private_key": "7bab70e95cb585ea052c3aeb27de0afa9897ba5746276aa1c25310383216ceb860eb82baacbc940e710a40f21f962a3651013b90c23ece31606752f298c38d90",
        "type": "default"
      }
    },
    "signer": "p1"
  }

In environment variables:

.. code-block:: bash

  IROHA_CRYPTO_PROVIDERS_0_KEY=p1
  IROHA_CRYPTO_PROVIDERS_0_CRYPTO_TYPE=ed25519_sha3_256
  IROHA_CRYPTO_PROVIDERS_0_PRIVATE_KEY=cc5013e43918bd0e5c4d800416c88bed77892ff077929162bb03ead40a745e88
  IROHA_CRYPTO_PROVIDERS_0_TYPE=default
  IROHA_CRYPTO_PROVIDERS_1_KEY=p2
  IROHA_CRYPTO_PROVIDERS_1_CRYPTO_TYPE=ed25519_sha2_256
  IROHA_CRYPTO_PROVIDERS_1_PRIVATE_KEY=7bab70e95cb585ea052c3aeb27de0afa9897ba5746276aa1c25310383216ceb860eb82baacbc940e710a40f21f962a3651013b90c23ece31606752f298c38d90
  IROHA_CRYPTO_PROVIDERS_1_TYPE=default
  IROHA_CRYPTO_SIGNER=p1


Logging
=======

In Iroha logging can be adjusted as granularly as you want.
Each component has its own logging configuration with properties inherited from
its parent, able to be overridden through config file.
This means all the component loggers are organized in a tree with a single root.
The relevant section of the configuration file contains the overriding values:

In configuration file:

.. code-block:: javascript

  "log": {
    "level": "trace",
    "patterns": {
      "debug": "don't panic, it's %v.",
      "error": "MAMA MIA! %v!"
    },
    "children": {
      "KeysManager": {
        "level": "trace"
      },
      "Irohad": {
        "children": {
          "Storage": {
            "level": "trace",
            "patterns": {
              "debug": "thread %t: %v."
            }
          }
        }
      }
    }
  }

In environment variables:

.. code-block:: bash

  IROHA_LOG_LEVEL=trace
  IROHA_LOG_PATTERNS_0_KEY=debug
  IROHA_LOG_PATTERNS_0="don't panic, it's %v."
  IROHA_LOG_PATTERNS_1_KEY=error
  IROHA_LOG_PATTERNS_1="MAMA MIA! %v!"
  IROHA_LOG_CHILDREN_0_KEY=KeysManager
  IROHA_LOG_CHILDREN_0_LEVEL=trace
  IROHA_LOG_CHILDREN_1_KEY=Irohad
  IROHA_LOG_CHILDREN_1_CHILDREN_0_KEY=Storage
  IROHA_LOG_CHILDREN_1_CHILDREN_0_LEVEL=trace
  IROHA_LOG_CHILDREN_1_CHILDREN_0_PATTERNS_0_KEY=debug
  IROHA_LOG_CHILDREN_1_CHILDREN_0_PATTERNS_0="thread %t: %v."

Every part of this config section is optional.

- ``level`` sets the verbosity.
  Available values are (in decreasing verbosity order):

  - ``trace`` - print everything
  - ``debug``
  - ``info``
  - ``warning``
  - ``error``
  - ``critical`` - print only critical messages

- ``patterns`` controls the formatting of each log string for different
  verbosity levels.
  Each value overrides the less verbose levels too.
  So in the example above, the "don't panic" pattern also applies to info and
  warning levels, and the trace level pattern is the only one that is not
  initialized in the config (it will be set to default hardcoded value).

.. note::  Even if multiple patterns are specified for a single component, this component will use only one pattern — the one that corresponds to selected logging level. However, the patterns will be inherited and can be used in the child loggers.

- ``children`` describes the overrides of child nodes.
  The keys are the names of the components, and the values have the same syntax
  and semantics as the root log configuration.
