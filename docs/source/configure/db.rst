======================
PostgreSQL vs. RocksDB
======================

When you use Iroha, you have a choice of building and using it with either PostgreSQL (relational database) or RocksDB (key-value).

Both options are reliable and can be used in production environment but there are some key differences we would like to tell you about that might help you make your choice. 

Specific features of PostgreSQL:
********************************

- Classic database option -- which means that there are many tools to work with it;
- When Iroha is working in Docker, PostgreSQL runs in a separate container;
- With a lot of data PostgreSQL might become slower

.. tip:: You can learn more about this database in its documentation: https://www.postgresql.org/docs/

Specific features of RocksDB:
*****************************

- Fast (see `performance testing results <https://wiki.hyperledger.org/display/iroha/Release+1.3.0>`_);
- RocksDB is embedded -- both WSV and blockstore are in the same database which means more consistency, but there is a possibility of manually adding a hash with access to the database which might cause some security-related concerns;
- Takes less space on the disk and there is no information that it could grow too big

.. tip:: You can learn more about this database in its documentation: https://rocksdb.org/docs/getting-started.html
