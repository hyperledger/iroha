Starting Iroha node with existing WSV
=====================================
This will explain some details about reusing existing world state view (aka WSV) database when starting a node in order to minimize the startup.

Please consider the following specifics of reusing WSV, compared to restoring it from block storage:

// table or whatever
trust point
reuse: we need to rely on both blockstorage and WSV.
restore: we trust only the genesis block.

integrity
reuse: blockstorage and WSV must match each other! iroha will not verify that.
restore: iroha will check every block while restoring WSV. any error in blockstorage will be found (except genesis block, of course). WSV is guaranteed to match the blockstorage.

time
reuse: iroha is almost immediately ready to operate in the network.
restore: the larger blockstorage - the longer time to restore and begin operation.



Enabling WSV Reuse
^^^^^^^^^^^^^^^^^^

If you want to reuse WSV state, start Iroha with `--reuse_state` flag.
Given this flag, Iroha will not reset or overwrite the state database if it fails to start for whatever reason.

State Database Schema version
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When reusing existing WSV, iroha performs a schema version compatibility check.
It will not start or somehow alter a database if its schema is not compatible with the binary.

If your schema was created by iroha of version v1.1.1 or lower, most probably it does not include the version information.
In this case you need to add it manually.
You are encouraged to use our script for this purpose, it is located `here <https://github.com/hyperledger/iroha-state-migration-tool/blob/master/state_migration.py>`__.
To forcefully (i.e. without any `migration process <#changing-iroha-version-migration>`__) set your schema version, launch the script with `--force_schema_version` flag and pass the version of Iroha binary that was used to create your schema.

.. warning::
  Before forcefully writing the schema version numbers, double check the version of irohad that created the schema.
  No checks are performed when you force schema numbers, hence it is easy to break the state database in the future (during the next migration).

Changing Iroha version. Migration.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In case you want to change Iroha version while keeping the WSV, you are encouraged to perform a migration.
Although it might be not necessary (Iroha will refuse to start if the schema is incompatible), generally, we improve the schema and migration will help Iroha perform better and the sun shine brighter blah blah.
You are encouraged to perform a database backup before migration using standard PostgreSQL guidelines for that.

To perform migration, please use our `script <https://github.com/hyperledger/iroha-state-migration-tool/blob/master/state_migration.py>`__.
It will load the schema information from the database and match it with migration steps (by default, migration scenarios are defined in ``migration_data`` directory in the same folder as the script).
Then it will find all migration paths that will transition your database to the desired version and ask you to choose one.
