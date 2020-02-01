.. raw:: html

    <style> .red {color:#aa0060; font-weight:bold; font-size:16px} </style>

.. role:: red

Restarting Iroha node with existing WSV
=======================================

Previously, in cases when you had to update a node or it shut down for some reason, there was only one option of re-reading all of the blocks to recreate consistent `world state view (aka WSV) <../concepts_architecture/architecture.html#world-state-view>`__.
To start up a node quicker, it is now possible to reuse an existing WSV database after a quick check.
For that, ``hash`` of the top block and the ``height`` of the blockstorage are included in the WSV.

.. warning::
	It is up to Administrators of the node to make sure the WSV is not edited in any way thus not compromising the consistency of the network.

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

WSV Database Schema version
^^^^^^^^^^^^^^^^^^^^^^^^^^^

When reusing existing WSV, Iroha performs a schema version compatibility check.
It will not start or somehow alter the database, if its schema is not compatible with the Iroha in use.

If your schema was created by Iroha of version v1.1.1 or lower, most likely it does not include the version information.
In this case you need to add it manually.
You are encouraged to use our script for this purpose, it is located `here <https://github.com/hyperledger/iroha/blob/master/utils/wsv_migration.py>`__.
To forcefully (i.e. without any `migration process <#changing-iroha-version-migration>`__) set a schema to given numbers, launch it with `--force_schema_version` flag and pass the values from the table below:

+------------------------+--------+--------+--------+--------+
| Number / Iroha version | v1.0.0 | v1.0.1 | v1.1.0 | v1.1.1 |
+========================+========+========+========+========+
| iroha_version_major    |    1   |    1   |    1   |    1   |
+------------------------+--------+--------+--------+--------+
| iroha_version_minor    |    0   |    0   |    1   |    1   |
+------------------------+--------+--------+--------+--------+
| iroha_version_minor    |    0   |    1   |    0   |    1   |
+------------------------+--------+--------+--------+--------+
| iroha_version_patch    |    0   |    0   |    0   |    0   |
+------------------------+--------+--------+--------+--------+
| db_version_major       |    1   |    1   |    1   |    1   |
+------------------------+--------+--------+--------+--------+
| db_version_minor       |    0   |    0   |    0   |    0   |
+------------------------+--------+--------+--------+--------+

Changing Iroha version. Migration.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In case you want to change Iroha version while keeping the WSV, you are encouraged to perform a migration.
Although it might be unnecessary (Iroha will refuse to start if the schema is incompatible), as a general rule, we improve the schema with each version and migration might be a good idea for a better performance.
You are encouraged to perform a database backup before migration using standard `PostgreSQL guidelines <https://www.postgresql.org/docs/current/backup.html>`__ for that.

To perform migration, please use our `script <https://github.com/hyperledger/iroha/blob/master/utils/wsv_migration.py>`__.
It will load the schema information from the database and match it with migration steps (by default, migration scenarios are defined in ``migration_data`` directory in the same folder as the script).
Then it will find all migration paths that will transition your database to the desired version and ask you to choose one.
