.. raw:: html

    <style> .red {color:#aa0060; font-weight:bold; font-size:16px} </style>

.. role:: red

Restarting Iroha node with existing WSV
=======================================

Previously, in cases when you had to update a node or it shut down for some reason, there was only one option of re-reading all of the blocks to recreate consistent `world state view (aka WSV) <../concepts_architecture/architecture.html#world-state-view>`__.
To start up a node quicker, it is now possible to reuse an existing WSV database after a quick check.
For that, ``hash`` of the top block and the ``height`` of the blockstorage are included in the WSV.

.. warning::
	It is up to Administrators of the node to make sure the WSV is not edited manually – only by Iroha or the `migration script <#changing-iroha-version-migration>`__.
	Manual editing or editing of the migration script not following a trustworthy guideline can lead to inconsistent network.
	Only do so at your own risk (we warned you).

Although it can be a great idea for some of the cases, but please consider that there are certain specifics of reusing WSV, compared to restoring it from blockstorage:

| :red:`Trust point`
| **Reusing WSV:** we need to rely on both blockstorage and WSV.
| **Restore WSV from block storage:** we trust only the genesis block.


| :red:`Integrity`
| **Reusing WSV:** blockstorage and WSV must match each other! Iroha will not check for that.
| **Restore WSV from block storage:** Iroha will check every block, while restoring WSV.
	Any error in blockstorage will be found (except genesis block, of course).
	WSV is guaranteed to match the blockstorage.

| :red:`Time`
| **Reusing WSV:** Iroha is almost immediately ready to operate in the network.
| **Restore WSV from block storage:** the larger blockstorage - the longer it takes to restore it and begin operation.

.. note:: If the local ledger that shut down has more blocks than it should and the correct WSV is among them - it is ok, Iroha will take the WSV of the correct block.
	If blocks are less than should be – the option of reusing WSV will not work for you.
	Please, restore it from blocks.


Dropping WSV
^^^^^^^^^^^^^^^^^^

By default Iroha reuses WSV state on startup, so there is no need in `--reuse_state` flag anymore. However, it is left for backward compatibility.
If you want to drop WSV state, start Iroha with '--drop_state' flag. Given this flag, Iroha will reset and overwrite the state database.

State Database Schema version
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When reusing existing WSV, Iroha performs a schema version compatibility check.
It will not start or somehow alter the database, if its schema is not compatible with the Iroha in use.

If your schema was created by Iroha of version v1.1.1 or lower, most likely it does not include the version information.
In this case you need to add it manually.
You are encouraged to use our script for this purpose, it is located `here <https://github.com/hyperledger/iroha-state-migration-tool/blob/master/state_migration.py>`__.
To forcefully (i.e. without any `migration process <#changing-iroha-version-migration>`__) set your schema version, launch the script with `--force_schema_version` flag and pass the version of Iroha binary that was used to create your schema.

.. warning::
  Before forcefully writing the schema version numbers, double check the version of irohad that created the schema.
  No checks are performed when you force schema numbers, hence it is easy to break the state database in the future (during the next migration).

Changing Iroha version. Migration.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In case you want to change Iroha version while keeping the WSV, you are encouraged to perform a migration.
Although it might be unnecessary (Iroha will refuse to start if the schema is incompatible), as a general rule, we improve the schema with each version and migration might be a good idea for a better performance.
You are encouraged to perform a database backup before migration using standard `PostgreSQL guidelines <https://www.postgresql.org/docs/current/backup.html>`__ for that.

To perform migration, please use our `script <https://github.com/hyperledger/iroha-state-migration-tool/blob/master/state_migration.py>`__.

It will load the schema information from the database and match it with migration steps (by default, migration scenarios are defined in ``migration_data`` directory in the same folder as the script).
Then it will find all migration paths that will transition your database to the desired version and ask you to choose one.

.. seealso::
	`Here <https://github.com/hyperledger/iroha-state-migration-tool/blob/master/README.md>`_ are some details about different migration cases and examples you can check out to perform migration

Synchronize WSV mode.
^^^^^^^^^^^^^^^^^^^^^

Specify '--wait_for_new_blocks' options for WSV synchronization mode. Iroha restores WSV from blockstore and waits for new blocks to be added externally. In this mode Iroha will not perform network operations.
