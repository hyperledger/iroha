irohad Flags
================

You can start ``irohad`` with different flags.
Some of the main ones `were already mentioned <single.html#run-iroha-daemon-irohad>`_ but there are others, that you might find useful for your unique situation.
Here they are: 

+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| Flag                    | Description                                                         | Type            | Default        |
+=========================+=====================================================================+=================+================+
| ``-config``             | specifies Iroha provisioning path                                   | ``string``      | ""             |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-drop_state``         | drops existing state data at startup                                | ``bool``        | false          |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-genesis_block``      | specifies file with initial block                                   | ``string``      | ""             |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-keypair_name``       | specifies name of .pub and .priv files                              | ``string``      | ""             |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-metrics_addr``       | Prometeus HTTP server listen address                                | ``string``      | "127.0.0.1"    |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-metrics_port``       | Prometeus HTTP server listens port, disabled by default             | ``string``      | ""             |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-overwrite_ledger``   | overwrites ledger data if existing                                  | ``bool``        | false          |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-reuse_state``        | tries to reuse existing state data at startup (Deprecated, startup  | ``bool``        | true           |
|                         | reuses state by default. Use ``drop_state`` to drop the WSV)        |                 |                |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-verbosity``          | log verbosity                                                       | ``string``      | "config_file"  |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
| ``-wait_for_new_blocks``| startup synchronization policy - waits for new blocks in blockstore,| ``bool``        | false          |
|                         | does not run network                                                |                 |                |
+-------------------------+---------------------------------------------------------------------+-----------------+----------------+
