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


WSV Database Schema version
^^^^^^^^^^^^^^^^^^^^^^^^^^^

When reusing existing WSV, iroha performs a schema version compatibility check.
It will not start or somehow alter a database if its schema is not compatible with the binary.

If your schema was created by iroha of version v1.1.1 or lower, most probably it does not include the version information.
In this case you need to add it manually.
You are encouraged to use our script for this purpose, it is located in iroha repo: https://github.com/hyperledger/iroha/blob/master/utils/wsv_migration.py
To forcefully (ie without any migration process) set a schema to given numbers, launch it with `--force_schema_version` flag and pass the values from the table below:

+------------------------+--------+--------+--------+--------+
| Number \ Iroha version | v1.0.0 | v1.0.1 | v1.1.0 | v1.1.1 |
+------------------------+--------+--------+--------+--------+
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
Although it might be not necessary (Iroha will refuse to start if the schema is incompatible), generally, we improve the schema and migration will help Iroha perform better and the sun shine brighter blah blah.
You are encouraged to perform a database backup before migration using standard PostgreSQL guidelines for that.

To perform a migration, please use our script https://github.com/hyperledger/iroha/blob/master/utils/wsv_migration.py
It will load the schema information from the database and match it with migration steps that it knows about (by default, migration scenarios are read from directory named `migration_data`.
Then it will find all migration paths that will transition your database to the desired version and ask you to choose one.
