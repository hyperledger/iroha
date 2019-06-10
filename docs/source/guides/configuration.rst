.. _configuration:

Configuration
=============

In this section we will understand how to configure Iroha. Let's take a look
at ``example/config.sample``

.. code-block:: javascript
  :linenos:

  {
    "block_store_path": "/tmp/block_store/",
    "torii_port": 50051,
    "internal_port": 10001,
    "pg_opt": "host=localhost port=5432 user=postgres password=mysecretpassword dbname=iroha",
    "max_proposal_size": 10,
    "proposal_delay": 5000,
    "vote_delay": 5000,
    "mst_enable" : false,
    "mst_expiration_time" : 1440,
    "max_rounds_delay": 3000,
    "stale_stream_max_rounds": 2
  }

As you can see, configuration file is a valid ``json`` structure. Let's go
line-by-line and understand what every parameter means.

Deployment-specific parameters
------------------------------

- ``block_store_path`` sets path to the folder where blocks are stored.
- ``torii_port`` sets the port for external communications. Queries and
  transactions are sent here.
- ``internal_port`` sets the port for internal communications: ordering
  service, consensus and block loader.
- ``pg_opt`` is used for setting credentials of PostgreSQL: hostname, port,
  username, password and database name.
  All data except the database name are mandatory.
  If database name is not provided, a default one gets used.
- ``log`` is an optional parameter controlling log output verbosity and format
  (see below).

.. warning:: Unspecified database name support is deprecated and will be removed!

Environment-specific parameters
-------------------------------

- ``max_proposal_size`` is the maximum amount of transactions that can be in
  one proposal, and as a result in a single block as well. So, by changing this
  value you define the size of potential block. For a starter you can stick to
  ``10``. However, we recommend to increase this number if you have a lot of
  transactions per second.
- ``proposal_delay`` is a timeout in milliseconds that a peer waits a response
  from the orderding service with a proposal.
- ``vote_delay`` is a waiting time in milliseconds before sending vote to the
  next peer. Optimal value depends heavily on the amount of Iroha peers in the
  network (higher amount of nodes requires longer ``vote_delay``). We recommend
  to start with 100-1000 milliseconds.
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
- ``max_rounds_delay`` is an optional parameter specifying the maximum delay
  between two consensus rounds (in milliseconds).
  The default value is 3000.
  When Iroha is idle, it gradually increases the delay to reduce CPU, network
  and logging load.
  However too long delay may be unwanted when first transactions arrive after a
  long idle time.
  This parameter allows users to find an optimal value in a tradeoff between
  resource consumption and the delay of getting back to work after an idle
  period.
- ``stale_stream_max_rounds`` is an optional parameter specifying the maximum
  amount of rounds to keep an open status stream while no status update is
  reported.
  The default value is 2.
  Increasing this value reduces the amount of times a client must reconnect to
  track a transaction if for some reason it is not updated with new rounds.
  However large values increase the average number of connected clients during
  each round.
- ``"initial_peers`` is an optional parameter specifying list of peers a node
  will use after startup instead of peers from genesis block.
  It could be useful when you add a new node to the network where the most of
  initial peers may become malicious.
  Peers list should be provided as a JSON array:

  ``"initial_peers" : [{"address":"127.0.0.1:10001", "public_key":
  "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"}]``

Logging
-------

In Iroha logging can be adjusted as granularly as you want.
Each component has its own logging configuration with properties inherited from
its parent, able to be overridden through config file.
This means all the component loggers are organized in a tree with a single root.
The relevant section of the configuration file contains the overriding values:

.. code-block:: javascript
  :linenos:

  "log": {
    "level": "info",
    "patterns": {
      "debug": "don't panic, it's %v.",
      "error": "MAMA MIA! %v!!!"
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
- ``children`` describes the overrides of child nodes.
  The keys are the names of the components, and the values have the same syntax
  and semantics as the root log configuration.
