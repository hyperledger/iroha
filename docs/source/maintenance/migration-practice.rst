========================
Good Migration Practices
========================

Iroha maintainers often receive questions about the best ways to migrate projects to new versions of Iroha, so we decided to share our practices that worked the best for us and our projects.

**On an example of a 4 peer network we will go through a migration procedure (also moving from PostgeSQL database to RocksDB) that turned out to be the most stable and reliable in our projects.**

Here are the steps:
*******************

1. You have the 4 nodes running Iroha with the old version on Postgres
2. Follow the instructions on `Iroha Database migration <migration-rocksdb.html>`_. Copy the RocksDB folder. *Skip this step if you do not need to switch between Postgres and RocksDB*
3. Add a new peer running the new version of Iroha using the `Add Peer command <add_peer.html>`_ and with the RocksDB folder on it.
4. Add similar nodes 2 more times
5. Now you have 7 nodes -- 4 running the old version and 3 running the new one
6. Switch off the first node with the old version and update this node with the same key pair to the new version (with RocksDB, if that is your goal) 
7. Repeat this for every node with the old Iroha version
8. Now you can remove the "new" nodes and continue the work on your project!

 