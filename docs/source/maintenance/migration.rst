====================
Migration To RocksDB
====================

Iroha allows for using Postgres or Rocks Database.
You can use the option you prefer and if you want to switch -- there is an option for you.
**Just migrate your database!**
Here is how

.. hint:: Both migration tool and WSV checker have ``-help`` that you can call to check the available flags anytime.

How to migrate
==============

After you built Iroha (or simply run it) after version Iroha 1.3 you already have the migration tools as a separate executable! 

Just run the ``irohad/iroha-migrate`` with the following flags:

- ``-help`` - help
- ``-block_store_path`` - specifies path to block store. Default: "/tmp/block_store"
- ``-export`` - exports block store to specified directory, default CWD. Use it to *reverse* migration to RocksDB (by exporting files from it).
- ``-force`` - use it to override blocks in RocksDB blockstore if it already exists. This might be very useful if the next step - checking the correctness of the migrated database - goes through with errors and you need to repeat the migration process. Default: false
- ``-rocksdb_path`` - specifies the path to RocksDB. Default: "rocks.db"

And your database is migrated! But that is not all.

To make sure that your migration process has been successful, please then use the WSV check.

How to check WSV after the migration
====================================

Run ``irohad/wsv_check`` with the following flags: 

- ``-help`` - help
- ``-pg_opt`` - specifies Postgres options line. It should be as in your configuration. Default: "dbname=iroha_default host=localhost port=5432 user=postgres password=postgres"
- ``-rocksdb_path`` - specifies path to the RocksDB. Default: "rocks.db"

If the databases are the same, you will see Mr. Spock. Also, (if you are not much of a sci-fi fan) the exit code will be zero.

If not, there will be the differences in the databases: the data on the left is what is indicated in the RocksDB and on the right -- what is in Postgres.
If there are differences, we would suggest to use the migration tool again with the ``-force`` flag.

In case of discrepancies, the command will exit with a non-zero code. Differences will be reported to the console and full WSVs of both DBs will be dumped to corresponding files (the output in the form of ``postgres.wsv`` and ``rocksdb.wsv`` will be in the CWD). 
For future investigation you can use any diff tool to see the exact differences between WSVs.