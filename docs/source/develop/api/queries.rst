Queries
=======

A query is a request related to certain part of World State View — the latest state of blockchain.
Query cannot modify the contents of the chain and a response is returned
to any client immediately after receiving peer has processed a query.

Validation
^^^^^^^^^^

The validation for all queries includes:

- timestamp — shouldn't be from the past (configurable in `Iroha configuration <../../configure/index.html#environment-specific-parameters>`_) or from the future (range of 5 minutes added to the peer time)
- signature of query creator — used for checking the identity of query creator
- query counter — checked to be incremented with every subsequent query from query creator
- roles — depending on the query creator's role: the range of state available to query can relate to to the same account, account in the domain, to the whole chain, or not allowed at all

Result Pagination
^^^^^^^^^^^^^^^^^

Some queries support `TxPaginationMeta` that allows to customise and sort the query result in different ways what could be used in development.
Pagination works together with ordering prameters, similar to `ORDER BY in SQL language <https://www.postgresql.org/docs/12/sql-select.html#SQL-ORDERBY>`_ – "the result rows are sorted according to the specified expression (in Iroha – Field). If two rows are equal according to the leftmost expression, they are compared according to the next expression and so on."

Here is how the "expression" is specified:

.. code-block:: proto

    enum Field {
        kCreatedTime = 0;
        kPosition = 1;
    }

There are 2 bases for ordering – on creation time and depending on the number of block.

There is an ascending and descending directions for each Field:

.. code-block:: proto

    enum Direction {
        kAscending = 0;
        kDescending = 1;
    }

Now, the ordering itself:

.. code-block:: proto

    message Ordering {
        message FieldOrdering {
          Field field = 1;
          Direction direction = 2;
        }
        repeated FieldOrdering sequence = 1;
    }

After ordering is specified, pagination can be executed:

.. literalinclude:: ../../../../shared_model/schema/queries.proto
    :language: proto
    :start-at: message TxPaginationMeta {
    :end-before: message AssetPaginationMeta {


What is added to the request structure in case of pagination
------------------------------------------------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Page size", "size of the page to be returned by the query, if the response contains fewer transactions than a page size, then next tx hash will be empty in response", "page_size > 0", "5"
    "First tx hash", "hash of the first transaction in the page. If that field is not set — then the first transactions are returned", "hash in hex format", "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"
    "ordering", "how the results should be ordered (before pagination is applied)", "see fields below", "see fields below"
    "ordering.sequence", "ordeing spec, like in SQL ORDER BY", "sequence of fields and directions", "[{kCreatedTime, kAscending}, {kPosition, kDescending}]"
    "First tx time", "time of the first transaction in query result. If that field is not set - then the transactions starting from first are returned", "Google Protocol Buffer Timestamp type", "0001-01-01T00:00:00Z <= first tx time <= 9999-12-31T23:59:59.999999999Z"
    "Last tx time", "time of the last transaction in query result. If that field is not set - then the transactions up to the last are returned", "Google Protocol Buffer Timestamp type", "0001-01-01T00:00:00Z <= last tx time <= 9999-12-31T23:59:59.999999999Z"
    "First tx height", "block height of the first transaction in query result. If that field is not set - then the transactions starting from height 1 are returned", "first tx height > 0", "4"
    "Last tx height", "block height of the last transaction in query result. If that field is not set - then the transactions up to the last one are returned", "last tx height > 0", "6"
    
Engine Receipts
^^^^^^^^^^^^^^^

Purpose
-------

Retrieve a receipt of a CallEngine command.
Similar to the eth.GetTransactionReceipt API call of Ethereum JSON RPC API.
Allows to access the event log created during computations inside the EVM.

Request Schema
--------------

.. code-block:: proto

   message GetEngineReceipts {
       string tx_hash = 1;     // hex string
   }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Transaction Hash", "hash of the transaction that has the CallEngine command", "hash in hex format", "5241f70cf3adbc180199c1d2d02db82334137aede5f5ed35d649bbbc75ab2634"

Response Schema
---------------

.. code-block:: proto

    message EngineReceiptsResponse {
        repeated EngineReceipt engine_receipt = 1;
    }
    message EngineReceipt {
        int32 command_index = 1;
        string caller = 2;
        oneof opt_to_contract_address {
            CallResult call_result = 3;
            string contract_address = 4;
        }
        repeated EngineLog logs = 5;
    }
    message CallResult {
        string callee = 1;
        string result_data = 2;
    }
    message EngineLog {
        string address = 1;         // hex string
        string data = 2;            // hex string
        repeated string topics = 3; // hex string
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "command_index", "Index of the CallEngine command in the transaction", "non-negative integer", "0"
    "caller", "caller account of the smart contract", "<account_name>@<domain_id>", "admin@test"
    "call_result.callee", "address of called contract", "20-bytes string in hex representation", "0000000000000000000000000000000000000000"
    "call_result.result_data", "the value returned by the contract", "string in hex representation", "00"
    "contract_address", "EVM address of a newly deployed contract", "20-bytes string in hex representation", "7C370993FD90AF204FD582004E2E54E6A94F2651"
    "logs", "Array of EVM event logs created during smart contract execution.", "see below", "see below"
    "logs.[].address", "the contract caller EVM address", "20-bytes string in hex representation", "577266A3CE7DD267A4C14039416B725786605FF4"
    "logs.[].data", "the logged data", "hex string", "0000000000000000000000007203DF5D7B4F198848477D7F9EE080B207E544DD000000000000000000000000000000000000000000000000000000000000006D"
    "logs.[].topics", "log topic as in Ethereum", "32-byte strings", "[3990DB2D31862302A685E8086B5755072A6E2B5B780AF1EE81ECE35EE3CD3345, 000000000000000000000000969453762B0C739DD285B31635EFA00E24C25628]"


Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "2", "No such permissions", "Query’s creator does not have any of the permissions to get the call engine receipt", "Grant the necessary permission"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

Get Account
^^^^^^^^^^^

Purpose
-------

Purpose of get account query is to get the state of an account.

Request Schema
--------------

.. code-block:: proto

    message GetAccount {
        string account_id = 1;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "account id to request its state", "<account_name>@<domain_id>", "alex@morgan"

Response Schema
---------------

.. code-block:: proto

    message AccountResponse {
        Account account = 1;
        repeated string account_roles = 2;
    }

    message Account {
        string account_id = 1;
        string domain_id = 2;
        uint32 quorum = 3;
        string json_data = 4;
    }


Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "account id", "<account_name>@<domain_id>", "alex@morgan"
    "Domain ID", "domain where the account was created", "RFC1035 [#f1]_, RFC1123 [#f2]_ ", "morgan"
    "Quorum", "number of signatories needed to sign the transaction to make it valid", "0 < quorum ≤ 128", "5"
    "JSON data", "key-value account information", "JSON", "{ genesis: {name: alex} }"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get account", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get account", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

Get Block
^^^^^^^^^

Purpose
-------

Purpose of get block query is to get a specific block, using its height as an identifier

Request Schema
--------------

.. code-block:: proto

    message GetBlock {
        uint64 height = 1;
    }


Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Height", "height of the block to be retrieved", "0 < height < 2^64", "42"

Response Schema
---------------

.. code-block:: proto

    message BlockResponse {
        Block block = 1;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Block", "the retrieved block", "block structure", "block"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get block", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have a permission to get block", "Grant `can_get_block <permissions.html#can-get-blocks>`__ permission"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"
    "3", "Invalid height", "Supplied height is not uint_64 or greater than the ledger's height", "Check the height and try again"

.. note::
    Error code 3 is ambiguous for this query.
    It indicates either invalid signatories or invalid height.
    Use this method with `height = 1` (first block is always present) to check for invalid signatories.

Get Signatories
^^^^^^^^^^^^^^^

Purpose
-------

Purpose of get signatories query is to get signatories, which act as an identity of the account.

Request Schema
--------------

.. code-block:: proto

    message GetSignatories {
        string account_id = 1;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "account id to request signatories", "<account_name>@<domain_id>", "alex@morgan"

Response Schema
---------------

.. code-block:: proto

    message SignatoriesResponse {
        repeated bytes keys = 1;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Keys", "an array of public keys", "`ed25519 <https://ed25519.cr.yp.to>`_", "292a8714694095edce6be799398ed5d6244cd7be37eb813106b217d850d261f2"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get signatories", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get signatories", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

Get Transactions
^^^^^^^^^^^^^^^^

Purpose
-------

GetTransactions is used for retrieving information about transactions, based on their hashes.

.. note:: This query is valid if and only if all the requested hashes are correct: corresponding transactions exist, and the user has a permission to retrieve them

Request Schema
--------------

.. code-block:: proto

    message GetTransactions {
        repeated bytes tx_hashes = 1;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Transactions hashes", "an array of hashes", "array with 32 byte hashes", "{hash1, hash2…}"

Response Schema
---------------

.. code-block:: proto

    message TransactionsResponse {
        repeated Transaction transactions = 1;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Transactions", "an array of transactions", "Committed transactions", "{tx1, tx2…}"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get transactions", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get transactions", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"
    "4", "Invalid hash", "At least one of the supplied hashes either does not exist in user's transaction list or creator of the query does not have permissions to see it", "Check the supplied hashes and try again"

Get Pending Transactions
^^^^^^^^^^^^^^^^^^^^^^^^

Purpose
-------

GetPendingTransactions is used for retrieving a list of pending (not fully signed) `multisignature transactions <../../concepts_architecture/glossary.html#multisignature-transactions>`_
or `batches of transactions <../../concepts_architecture/glossary.html#batch-of-transactions>`__ issued by account of query creator.

.. note:: This query uses `pagination <#result-pagination>`_ for quicker and more convenient query responses. Please read about it and specify pagination before sending the query request as well as `the request structure <#what-is-added-to-the-request-structure-in-case-of-pagination>`_.

Request Schema
--------------

.. code-block:: proto

    message GetPendingTransactions {
        TxPaginationMeta pagination_meta = 1;
    }

All the user's semi-signed multisignature (pending) transactions can be queried.
Maximum amount of transactions contained in a response can be limited by **page_size** field.
All the pending transactions are stored till they have collected enough signatures or get expired.
The mutual order of pending transactions or batches of transactions is preserved for a user.
That allows a user to query all transactions sequentially - page by page.
Each response may contain a reference to the next batch or transaction that can be queried.
A page size can be greater than the size of the following batch (in transactions).
In that case, several batches or transactions will be returned.
During navigating over pages, the following batch can collect the missing signatures before it gets queried.
This will result in stateful failed query response due to a missing hash of the batch.

Example
-------

If there are two pending batches with three transactions each and a user queries pending transactions
with page size 5, then the transactions of the first batch will be in the response and a reference
(first transaction hash and batch size, even if it is a single transaction in fact) to the second batch
will be specified too.
Transactions of the second batch are not included in the first response because the batch cannot be divided
into several parts and only complete batches can be contained in a response.

Response Schema
---------------

.. code-block:: proto

    message PendingTransactionsPageResponse {
        message BatchInfo {
            string first_tx_hash = 1;
            uint32 batch_size = 2;
        }
        repeated Transaction transactions = 1;
        uint32 all_transactions_size = 2;
        BatchInfo next_batch_info = 3;
    }

Response Structure
------------------

The response contains a list of `pending transactions <../../concepts_architecture/glossary.html#pending-transactions>`_,
the amount of all stored pending transactions for the user
and the information required to query the subsequent page (if exists).

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

        "Transactions", "an array of pending transactions", "Pending transactions", "{tx1, tx2…}"
        "All transactions size", "the number of stored transactions", "all_transactions_size >= 0", "0"
        "Next batch info", "A reference to the next page - the message might be not set in a response", "", ""
        "First tx hash", "hash of the first transaction in the next batch",  "hash in hex format", "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"
        "Batch size", "Minimum page size required to fetch the next batch", "batch_size > 0", "3"

Get Pending Transactions (deprecated)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. warning::
  The query without parameters is deprecated now and will be removed in the following major Iroha release (2.0).
  Please use the new query version instead: `Get Pending Transactions <#get-pending-transactions>`__.

Purpose
-------

GetPendingTransactions is used for retrieving a list of pending (not fully signed) `multisignature transactions <../../concepts_architecture/glossary.html#multisignature-transactions>`_
or `batches of transactions <../../concepts_architecture/glossary.html#batch-of-transactions>`__ issued by account of query creator.

Request Schema
--------------

.. code-block:: proto

    message GetPendingTransactions {
    }

Response Schema
---------------

.. code-block:: proto

    message TransactionsResponse {
        repeated Transaction transactions = 1;
    }

Response Structure
------------------

The response contains a list of `pending transactions <../../concepts_architecture/glossary.html#pending-transactions>`_.

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

        "Transactions", "an array of pending transactions", "Pending transactions", "{tx1, tx2…}"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get pending transactions", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get pending transactions", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

Get Account Transactions
^^^^^^^^^^^^^^^^^^^^^^^^

Purpose
-------

In a case when a list of transactions per account is needed, `GetAccountTransactions` query can be formed.

.. note:: This query uses `pagination <#result-pagination>`_ for quicker and more convenient query responses. Please read about it and specify pagination before sending the query request as well as `the request structure <#what-is-added-to-the-request-structure-in-case-of-pagination>`_.

Request Schema
--------------

.. code-block:: proto

    message GetAccountTransactions {
        string account_id = 1;
        TxPaginationMeta pagination_meta = 2;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "account id to request transactions from", "<account_name>@<domain_id>", "makoto@soramitsu"

Response Schema
---------------

.. code-block:: proto

    message TransactionsPageResponse {
        repeated Transaction transactions = 1;
        uint32 all_transactions_size = 2;
        oneof next_page_tag {
            string next_tx_hash = 3;
        }
    }

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get account transactions", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get account transactions", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"
    "4", "Invalid pagination hash", "Supplied hash does not appear in any of the user's transactions", "Make sure hash is correct and try again"
    "5", "Invalid account id", "User with such account id does not exist", "Make sure account id is correct"

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Transactions", "an array of transactions for given account", "Committed transactions", "{tx1, tx2…}"
    "All transactions size", "total number of transactions created by the given account", "", "100"
    "Next transaction hash", "hash pointing to the next transaction after the last transaction in the page. Empty if a page contains the last transaction for the given account", "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"

Get Account Asset Transactions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Purpose
-------

`GetAccountAssetTransactions` query returns all transactions associated with given account and asset.

.. note:: This query uses `pagination <#result-pagination>`_ for quicker and more convenient query responses. Please read about it and specify pagination before sending the query request as well as `the request structure <#what-is-added-to-the-request-structure-in-case-of-pagination>`_.

Request Schema
--------------

.. code-block:: proto

    message GetAccountAssetTransactions {
        string account_id = 1;
        string asset_id = 2;
        TxPaginationMeta pagination_meta = 3;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "account id to request transactions from", "<account_name>@<domain_id>", "makoto@soramitsu"
    "Asset ID", "asset id in order to filter transactions containing this asset", "<asset_name>#<domain_id>", "jpy#japan"

Response Schema
---------------

.. code-block:: proto

    message TransactionsPageResponse {
        repeated Transaction transactions = 1;
        uint32 all_transactions_size = 2;
        oneof next_page_tag {
            string next_tx_hash = 3;
        }
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Transactions", "an array of transactions for given account and asset", "Committed transactions", "{tx1, tx2…}"
    "All transactions size", "total number of transactions for given account and asset", "", "100"
    "Next transaction hash", "hash pointing to the next transaction after the last transaction in the page. Empty if a page contains the last transaction for given account and asset", "bddd58404d1315e0eb27902c5d7c8eb0602c16238f005773df406bc191308929"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get account asset transactions", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get account asset transactions", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"
    "4", "Invalid pagination hash", "Supplied hash does not appear in any of the user's transactions", "Make sure hash is correct and try again"
    "5", "Invalid account id", "User with such account id does not exist", "Make sure account id is correct"
    "6", "Invalid asset id", "Asset with such asset id does not exist", "Make sure asset id is correct"

Get Account Assets
^^^^^^^^^^^^^^^^^^

Purpose
-------

To get the state of all assets in an account (a balance), `GetAccountAssets` query can be used.

Request Schema
--------------

.. code-block:: proto

    message AssetPaginationMeta {
        uint32 page_size = 1;
        oneof opt_first_asset_id {
            string first_asset_id = 2;
        }
    }

    message GetAccountAssets {
        string account_id = 1;
        AssetPaginationMeta pagination_meta = 2;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "account id to request balance from", "<account_name>@<domain_id>", "makoto@soramitsu"
    AssetPaginationMeta.page_size, "Requested page size. The number of assets in response will not exceed this value. If the response was truncated, the asset id immediately following the returned ones will be provided in next_asset_id.", 0 < page_size < 32 bit unsigned int max (4294967296), 100
    AssetPaginationMeta.first_asset_id, "Requested page start.  If the field is not set, then the first page is returned.", name#domain, my_asset#my_domain

Response Schema
---------------
.. code-block:: proto

    message AccountAssetResponse {
        repeated AccountAsset account_assets = 1;
        uint32 total_number = 2;
        oneof opt_next_asset_id {
            string next_asset_id = 3;
        }
    }

    message AccountAsset {
        string asset_id = 1;
        string account_id = 2;
        string balance = 3;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Asset ID", "identifier of asset used for checking the balance", "<asset_name>#<domain_id>", "jpy#japan"
    "Account ID", "account which has this balance", "<account_name>@<domain_id>", "makoto@soramitsu"
    "Balance", "balance of the asset", "No less than 0", "200.20"
    total_number, number of assets matching query without page limits, 0 < total_number < 32 bit unsigned int max (4294967296), 100500
    next_asset_id, the id of asset immediately following curent page, name#domain, my_asset#my_domain

.. note::
   If page size is equal or greater than the number of assets matching other requested criteria, the next asset id will be unset in the response.
   Otherwise, it contains the value that clients should use for the first asset id if they want to fetch the next page.


Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get account assets", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get account assets", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"
    "4", "Invalid pagination metadata", "Wrong page size or nonexistent first asset", "Set a valid page size, and make sure that asset id is valid, or leave first asset id unspecified"

Get Account Detail
^^^^^^^^^^^^^^^^^^

Purpose
-------

To get details of the account, `GetAccountDetail` query can be used. Account details are key-value pairs, splitted into writers categories. Writers are accounts, that added the corresponding account detail. Example of such structure is:

.. code-block:: json

    {
        "account@a_domain": {
            "age": 18,
            "hobbies": "crypto"
        },
        "account@b_domain": {
            "age": 20,
            "sports": "basketball"
        }
    }

Here, one can see four account details - "age", "hobbies" and "sports" - added by two writers - "account@a_domain" and "account@b_domain". All of these details, obviously, are about the same account.

Request Schema
--------------

.. code-block:: proto

    message AccountDetailRecordId {
        string writer = 1;
        string key = 2;
    }

    message AccountDetailPaginationMeta {
        uint32 page_size = 1;
        AccountDetailRecordId first_record_id = 2;
    }

    message GetAccountDetail {
        oneof opt_account_id {
          string account_id = 1;
        }
        oneof opt_key {
          string key = 2;
        }
        oneof opt_writer {
          string writer = 3;
        }
        AccountDetailPaginationMeta pagination_meta = 4;
    }

.. note::
    Pay attention, that all fields except pagination meta are optional.
    The reasons for that are described below.

.. warning::
    Pagination metadata can be missing in the request for compatibility reasons, but this behaviour is deprecated and should be avoided.

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

        "Account ID", "account id to get details from", "<account_name>@<domain_id>", "account@domain"
        "Key", "key, under which to get details", "string", "age"
        "Writer", "account id of writer", "<account_name>@<domain_id>", "account@domain"
        AccountDetailPaginationMeta.page_size, "Requested page size. The number of records in response will not exceed this value. If the response was truncated, the record id immediately following the returned ones will be provided in next_record_id.", 0 < page_size < 32 bit unsigned int max (4294967296), 100
        AccountDetailPaginationMeta.first_record_id.writer, requested page start by writer, name#domain, my_asset#my_domain
        AccountDetailPaginationMeta.first_record_id.key, requested page start by key, string, age

.. note::
    When specifying first record id, it is enough to provide the attributes (writer, key) that are unset in the main query.

Response Schema
---------------

.. code-block:: proto

    message AccountDetailResponse {
        string detail = 1;
        uint64 total_number = 2;
        AccountDetailRecordId next_record_id = 3;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

        "Detail", "key-value pairs with account details", "JSON", "see below"
        total_number, number of records matching query without page limits, 0 < total_number < 32 bit unsigned int max (4294967296), 100
        next_record_id.writer, the writer account of the record immediately following curent page, <account_name>@<domain_id>, pushkin@lyceum.tsar
        next_record_id.key, the key of the record immediately following curent page, string, "cold and sun"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get account detail", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get account detail", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"
    "4", "Invalid pagination metadata", "Wrong page size or nonexistent first record", "Set valid page size, and make sure that the first record id is valid, or leave the first record id unspecified"

Usage Examples
--------------

Again, let's consider the example of details from the beginning and see how different variants of `GetAccountDetail` queries will change the resulting response.

.. code-block:: json

    {
        "account@a_domain": {
            "age": 18,
            "hobbies": "crypto"
        },
        "account@b_domain": {
            "age": 20,
            "sports": "basketball"
        }
    }

**account_id is not set**

If account_id is not set - other fields can be empty or not - it will automatically be substituted with query creator's account, which will lead to one of the next cases.

**only account_id is set**

In this case, all details about that account are going to be returned, leading to the following response:

.. code-block:: json

    {
        "account@a_domain": {
            "age": 18,
            "hobbies": "crypto"
        },
        "account@b_domain": {
            "age": 20,
            "sports": "basketball"
        }
    }

**account_id and key are set**

Here, details added by all writers under the key are going to be returned. For example, if we asked for the key "age", that's the response we would get:

.. code-block:: json

    {
        "account@a_domain": {
            "age": 18
        },
        "account@b_domain": {
            "age": 20
        }
    }

**account_id and writer are set**

Now, the response will contain all details about this account, added by one specific writer. For example, if we asked for writer "account@b_domain", we would get:

.. code-block:: json

    {
        "account@b_domain": {
            "age": 20,
            "sports": "basketball"
        }
    }

**account_id, key and writer are set**

Finally, if all three field are set, result will contain details, added the specific writer and under the specific key, for example, if we asked for key "age" and writer "account@a_domain", we would get:

.. code-block:: json

    {
        "account@a_domain": {
            "age": 18
        }
    }

Get Asset Info
^^^^^^^^^^^^^^

Purpose
-------

In order to get information on the given asset (as for now - its precision), user can send `GetAssetInfo` query.

Request Schema
--------------

.. code-block:: proto

    message GetAssetInfo {
        string asset_id = 1;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Asset ID", "asset id to know related information", "<asset_name>#<domain_id>", "jpy#japan"


Response Schema
---------------

.. code-block:: proto

    message Asset {
        string asset_id = 1;
        string domain_id = 2;
        uint32 precision = 3;
    }

.. note::
    Please note that due to a known issue you would not get any exception if you pass invalid precision value.
    Valid range is: 0 <= precision <= 255

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get asset info", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get asset info", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Asset ID", "identifier of asset used for checking the balance", "<asset_name>#<domain_id>", "jpy#japan"
    "Domain ID", "domain related to this asset", "RFC1035 [#f1]_, RFC1123 [#f2]_", "japan"
    "Precision", "number of digits after comma", "0 <= precision <= 255", "2"

Get Roles
^^^^^^^^^

Purpose
-------

To get existing roles in the system, a user can send `GetRoles` query to Iroha network.

Request Schema
--------------

.. code-block:: proto

    message GetRoles {
    }

Response Schema
---------------

.. code-block:: proto

    message RolesResponse {
        repeated string roles = 1;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Roles", "array of created roles in the network", "set of roles in the system", "{MoneyCreator, User, Admin, …}"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get roles", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get roles", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

Get Role Permissions
^^^^^^^^^^^^^^^^^^^^

Purpose
-------

To get available permissions per role in the system, a user can send `GetRolePermissions` query to Iroha network.

Request Schema
--------------

.. code-block:: proto

    message GetRolePermissions {
        string role_id = 1;
    }

Request Structure
-----------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Role ID", "role to get permissions for", "existing role in the system", "MoneyCreator"

Response Schema
---------------

.. code-block:: proto

    message RolePermissionsResponse {
        repeated string permissions = 1;
    }

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Permissions", "array of permissions related to the role", "string of permissions related to the role", "{can_add_asset_qty, …}"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get role permissions", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get role permissions", "Grant the necessary permission: individual, global or domain one"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

.. [#f1] https://www.ietf.org/rfc/rfc1035.txt
.. [#f2] https://www.ietf.org/rfc/rfc1123.txt


Get Peers
^^^^^^^^^

Purpose
-------

A query that returns a list of peers in Iroha network.

Request Schema
--------------

.. code-block:: proto

    message GetPeers {
    }

Response Schema
---------------

.. code-block:: proto

    message Peer {
        string address = 1;
        string peer_key = 2; // hex string
    }

    message PeersResponse {
        repeated Peer peers = 1;
    }

Response Structure
------------------

A list of peers with their addresses and public keys is returned.

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Peers", "array of peers from the network", "non-empty list of peers", "{Peer{""peer.domain.com"", ""292a8714694095edce6be799398ed5d6244cd7be37eb813106b217d850d261f2""}, …}"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get peers", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query creator does not have enough permissions to get peers", "Append a role with can_get_blocks or can_get_peers permission"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

.. warning::

    Currently Get Peers query uses "can_get_blocks" permission for compatibility purposes.
    Later that will be changed to "can_get_peers" with the next major Iroha release.

Fetch Commits
^^^^^^^^^^^^^

Purpose
-------

To get new blocks as soon as they are committed, a user can invoke `FetchCommits` RPC call to Iroha network.

Request Schema
--------------

No request arguments are needed


Response Schema
---------------

.. code-block:: proto

    message BlockQueryResponse {
        oneof response {
            BlockResponse block_response = 1;
            BlockErrorResponse block_error_response = 2;
        }
    }

    message BlockResponse {
        Block block = 1;
    }

    message BlockErrorResponse {
        string message = 1;
    }

Please note that it returns a stream of `BlockQueryResponse`.

Response Structure
------------------

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Block", "Iroha block", "only committed blocks", "{ 'block_v1': ....}"

Possible Stateful Validation Errors
-----------------------------------

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not get block streaming", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Query's creator does not have any of the permissions to get blocks", "Grant `can_get_block <permissions.html#can-get-blocks>`__ permission"
    "3", "Invalid signatures", "Signatures of this query did not pass validation", "Add more signatures and make sure query's signatures are a subset of account's signatories"

.. note::
    `BlockErrorResponse` contains only `message` field.
    In case of stateful validation error it will be "stateful invalid".
    `GetBlock <#get-block>`__ requires same `can_get_block <permissions.html#can-get-blocks>`__ permission.
    Therefore, it can be used with `height = 1` (first block is always present) to check for invalid signatories or insufficient permissions.

Example
-------
You can check an example how to use this query here:
https://github.com/x3medima17/twitter

