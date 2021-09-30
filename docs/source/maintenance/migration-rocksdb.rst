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

After you built Iroha (or simply pull the `Docker image <https://hub.docker.com/r/hyperledger/iroha>`_) version 1.3 (or later)  you already have the migration tools as a separate executable!
By default, after building, Iroha stores binaries to ``BUILD_DIR/bin/``. 

Just run the ``iroha_migrate`` with the following flags:

- ``-help`` - help
- ``-block_store_path`` - specifies path to block store. Default: "/tmp/block_store"
- ``-export`` - exports block store to specified directory, default -- current working directory (CWD). Use it to *reverse* migration to RocksDB (by exporting files from it).
- ``-drop_state`` - use it to override blocks in RocksDB blockstore if it already exists. This might be very useful if the next step - checking the correctness of the migrated database - goes through with errors and you need to repeat the migration process. Default: false
- ``-rocksdb_path`` - specifies the path to RocksDB. Default: "rocks.db"

.. raw:: html

   <details>

   <summary>In case of success you will see <b>this message</b></summary>

.. code-block:: bash

	Success! WSV in RocksDB was build.
	Next step check consintancy with Postgres WSV using iroha_wsv_diff.

.. raw:: html

   </details>
	<br/><div style="line-height: 0; padding: 0; margin: 1"></div>

If migration fails, it will exit with non-zero code. In this case, please check all the flags and try again.


And... your database is migrated! But that is not all.

To make sure that your migration process has been successful, please then use the WSV check.

How to check WSV after the migration
====================================

Run ``iroha_wsv_diff`` with the following flags: 

- ``-help`` - help
- ``-pg_opt`` - specifies Postgres options line. It should be as in your configuration. Default: "dbname=iroha_default host=localhost port=5432 user=postgres password=postgres"
- ``-rocksdb_path`` - specifies path to the RocksDB. Default: "rocks.db"

If the databases are the same, you will see Mr. Spock. Also, (if you are not much of a sci-fi fan) the exit code will be zero.

.. raw:: html

   <details>

   <summary>Successful check will result in <b>something like this</b></summary>

.. code-block:: bash

   Reading rocksdb... in 7112ms
	Reading postgres... in 5923ms
	See detailed dumps in files rockdb.wsv and postgres.wsv
	== VALIDATING ==
	left is rocksdb, right is postgres
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▓██████████▓▓▒░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓██████████████████▓▒░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒███████████▓▓▓███▓▓▓▓█▓░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓███████████████▓▓▓▓█████▒░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒████████▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓█▓░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░░▒█████████▓▓▓▒▒▒▒▒▒▒░▒▒▒▒▓▓░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░░▓▒▒░░░░▓▒▒▒░░░░░░░░░░░░░░░▒▓█████████▓████▓▒▒▒▓▓▓▓▓▒▓▒░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░░░▒▓▒▒░░░▒▒▒▒▒░░░░░░░░░░░░░░░▓████████▓█▓▓▒▓██▒▒▒▓▓▓▓▓▒▓▒░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░▒▒▒▒▒▒░░▒▒▒▒▒▒░░░░░░░░░░░░░░░▓███████▓▓▒▒▒▒▓██▒▒▒▒▒▒▒▒▒▓░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░░▓▒▒▒▒▒░░▒▒▒▒▒▒░░░░░░░░░░░░░░░░▓███████▓▓▒▒████▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░▒▓▒▒▒▒▒░▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░▒████████▓▓██████▓▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░████████████▓▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░▓▒▒▒▒▒▒▒▒▒▒▓▒▒▒░░░░░░░░░░░░░░░░░░▒███████▓▓▓▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░▓▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░██████▓▓██▓▓▓▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░▓█████▓▓▓▓▓▓▓▓▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░▒▒▒▒░░░░░░░░░░░░▓██████▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░▒▓▓▒▒░░░░░░░░░░░░░▓███████▓▓▓▓▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░▒████████████▓▓▒▒▒░░░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░▒▒███████████▓▓▒▒▒▒▒▒▓░░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░█▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░▒▒▒▒▓▓█████████▓▓▓▓▓▓▓▓██▓░░░░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░█▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░▒▓█████████▓██████████████████▓▓▒▒▒░░░░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░▒██▓▓▓▓▓▓▓▓▓▒▒▒░░░░▒▒▒▒▓▓▒▒▒▒▓▓▓▓▓▓▓▓█▓█████████████▓▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓▓▒░░░░▒▒▓▒▒▒░▒▒▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░
	░░░░░░░░░░░▒█▓▓▓▓▓▓▒▒▒▓░░░▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░
	░░░░░░░░░░▒████▓▓▓▒▒▒▓▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░
	░░░░░░░░░▒██████▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░
	░░░░░░░░▒██████▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░
	░░░░░░░░██████▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░
	░░░░░░░██████▓▓▓▒▓▓▒▒▓▓▒▒▒▓█▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░
	░░░░░▒█████▓▓▓▓▓▓▓▓█▓▓▒▒▒▒▒▒▓█▓▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░
	~~~ WSV-s are same. Enjoy Iroha with RocksDB ~~~




.. raw:: html

   </details>
	<br/><div style="line-height: 0; padding: 0; margin: 1"></div>

If not, there will be the differences in the databases: the data on the left is what is indicated in the RocksDB and on the right -- what is in Postgres.

.. raw:: html

   <details>

   <summary>Failed check will result in <b>something like this</b></summary>

.. code-block:: bash

	Reading rocksdb... in 6990ms
	Reading postgres... in 5652ms
	See detailed dumps in files rockdb.wsv and postgres.wsv
	== VALIDATING ==
	left is rocksdb, right is postgres
	Role-s 'client' have different permissions: '00000000000001110100100100000100100100011010111010000' and '00000000000001110100100100000100100100011010111010011'
	Wsv-s have different roles.
	AssetQuantity-s 'test#test' have different quantity: '0.0' and '1234567.0'
	Accounts 'superuser@bootstrap' have different assetsquantity
	Domains 'bootstrap' have different accounts.
	Wsv-s have different domains.
	~~~ WSV-s DIFFER!!! ~~~
	For future investigation use difftool on files rocksdb.wsv and postgres.wsv. Just like:
   		diff <(tail -n+2 postgres.wsv) <(tail -n+2 rockdb.wsv)




.. raw:: html

   </details>
	<br/><div style="line-height: 0; padding: 0; margin: 1"></div>

If there are differences, we would suggest to use the migration tool again with the ``-drop_state`` flag.

In case of discrepancies, the command will exit with a non-zero code. Differences will be reported to the console and full WSVs of both DBs will be dumped to corresponding files (the output in the form of ``postgres.wsv`` and ``rocksdb.wsv`` will be in the current working directory (CWD)). 
For future investigation you can use any diff tool to see the exact differences between WSVs.