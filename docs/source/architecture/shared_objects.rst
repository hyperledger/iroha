Iroha Shared Objects Description
================================

This document describes access to shared objects in a multithreaded scenario, whether or not is properly synchronized.

Document Structure
------------------

Each component in this document has its own diagram describing all members, and whether or not access to them is synchronized or not:

.. role:: clr

.. raw:: html

   <style>
      span.clr { background:#C5E1F8 !important ;
      padding: 4px;
      }
      tr td span.clr  {background:#C5E1F8 !important ;
      display: block;
      margin: -10px -16px -10px -16px;
      padding: 10px;
      padding-left: 16px;
      }
   </style>


* :clr:`Synchronized`
* Not Synchronized

Query Service
-------------

+---------------------------------+
| Query Service                   |
+=================================+
| :clr:`Cache`                    |
+---------------------------------+
| Query Processor                 |
+---------------------------------+

Query service is a grpc endpoint for queries from clients.
It has cache, from which it receives responses.
Access to the cache is protected by an internal mutex.
Query processor actually fetches data from the storage.
It is not synchronized here since all synchronization is internal.

Query Processor
---------------

+---------------------------------+
| Query Processor                 |
+=================================+
| :clr:`Query Response Observable`|
+---------------------------------+
| :clr:`Block Query Observable`   |
+---------------------------------+
| Storage                         |
+---------------------------------+

Transaction Service
-------------------

+---------------------------------+
| Transaction Service             |
+=================================+
| :clr:`Response Cache`           |
+---------------------------------+
| :clr:`Transaction Processor`    |
+---------------------------------+
| Storage                         |
+---------------------------------+

Transaction Service uses response cache to send transaction statuses.
Also, transaction processor is synchronized in status streaming.

Transaction Processor
---------------------

+------------------------------------+
| Transaction Processor              |
+====================================+
| Peer Communication Service         |
+------------------------------------+
| :clr:`Transaction Status Notifier` |
+------------------------------------+
| Proposal Set                       |
+------------------------------------+
| Candidate Set                      |
+------------------------------------+

Simulator
---------

+---------------------------------+
| Simulator                       |
+=================================+
| Proposal Notifier               |
+---------------------------------+
| Block Notifier                  |
+---------------------------------+
| Stateful Validator              |
+---------------------------------+
| Temporary Factory               |
+---------------------------------+
| Block Query                     |
+---------------------------------+

Synchronizer
------------

+---------------------------------+
| Synchronizer                    |
+=================================+
| Chain Validator                 |
+---------------------------------+
| Mutable Factory                 |
+---------------------------------+
| Block Loader                    |
+---------------------------------+

Yac Gate
--------

+---------------------------------+
| Yac Gate                        |
+=================================+
| Hash Gate                       |
+---------------------------------+
| Peer Orderer                    |
+---------------------------------+
| Hash Provider                   |
+---------------------------------+
| Block Creator                   |
+---------------------------------+
| Block Loader                    |
+---------------------------------+

Yac
---

+---------------------------------+
| Yac                             |
+=================================+
| :clr:`Yac Vote Storage`         |
+---------------------------------+
| :clr:`Yac Network`              |
+---------------------------------+


