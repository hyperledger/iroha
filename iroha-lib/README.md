# Hyperledger Iroha C++ library


**Current version of the library was tested and compatible with Iroha 1.5.0.**

The library was created to provide a convenient interface for C++ applications to communicate with [Iroha](https://github.com/hyperledger/iroha) blockchain. This includes sending transactions and queries, streaming transaction statuses and block commits.


# iroha-lib

Client library of [Iroha](https://github.com/hyperledger/iroha) written completely in modern C++.
Currently, the latest HL Iroha 1.5 release (`hyperledger/iroha:1.5.0` Docker image) is supported.


## Installation

Follow these steps to run the project:

1. Set up and run Iroha peer in a Docker container. [Follow the instructions from Iroha documentation](https://iroha.readthedocs.io/en/main/getting_started/).

2. Clone this repository.

3. Build the project:

``` bash
cmake --build ./build --target iroha_lib_model
```

4. Go to the `examples` directory:

``` bash
cd examples
```

5. Run the selected example:

``` bash
./tx_example
```

6. Check the logs to see if the scenario completed successfully.


## Examples

Examples describe how to establish connection with an Iroha peer which is running locally. The examples show how to create a new account and send assets to it. 

In `examples` directory you can find `TxExample.cpp`, `BatchExample.cpp` and `QueryExample.cpp` files. These files demonstrate main features of iroha-helpers. In the `TxExample.cpp` you can find how to build a transaction with several commands. The `BatchExample.cpp` explains how to deal with batch transactions.
Please explore [examples](https://github.com/hyperledger/iroha/tree/develop/iroha-lib/examples) directory for more usage examples.


## GrpcClient class

With GrpcClient you can create a connection with Iroha. Use one of the `send()` methods to do this.


### Create transaction

To create a transaction, you can call a command from a list of commands or create your own from scratch.

``` c++
iroha_lib::Tx(
	account_name,
	keypair)
	.createDomain(
		domain_id,
		user_default_role)
	.createAsset(
		asset_name,
		domain_id,
	    0)
.signAndAddSignature();
```


### Create batch

You can send transactions in batches. To create a batch, you need a list of defined transactions. The batch will only work if all the transactions in it pass validation. If at least one transaction doesn't pass validation, the whole batch is rejected.

Below is an example of creating a batch for two transactions:

``` c++
iroha_lib::TxBatch tx_batch;

std::vector<iroha::protocol::Transaction> transactions({tx_a, tx_b});

iroha_lib::GrpcClient(
	peer_ip,
	torii_port)
	.send(
		tx_batch
	.batch(transactions));
```


## Commands

- [x] [addAssetQuantity](https://iroha.readthedocs.io/en/main/develop/api/commands.html#add-asset-quantity)
- [x] [addPeer](https://iroha.readthedocs.io/en/main/develop/api/commands.html#add-peer)
- [x] [addSignatory](https://iroha.readthedocs.io/en/main/develop/api/commands.html#add-signatory)
- [x] [appendRole](https://iroha.readthedocs.io/en/main/develop/api/commands.html#append-role)
- [x] [createAccount](https://iroha.readthedocs.io/en/main/develop/api/commands.html#create-account)
- [x] [createAsset](https://iroha.readthedocs.io/en/main/develop/api/commands.html#create-asset)
- [x] [createDomain](https://iroha.readthedocs.io/en/main/develop/api/commands.html#create-domain)
- [x] [createRole](https://iroha.readthedocs.io/en/main/develop/api/commands.html#create-role)
- [x] [detachRole](https://iroha.readthedocs.io/en/main/develop/api/commands.html#detach-role)
- [x] [grantPermission](https://iroha.readthedocs.io/en/main/develop/api/commands.html#grant-permission)
- [x] [removeSignatory](https://iroha.readthedocs.io/en/main/develop/api/commands.html#remove-signatory)
- [x] [revokePermission](https://iroha.readthedocs.io/en/main/develop/api/commands.html#revoke-permission)
- [x] [setAccountDetail](https://iroha.readthedocs.io/en/main/develop/api/commands.html#set-account-detail)
- [x] [setAccountQuorum](https://iroha.readthedocs.io/en/main/develop/api/commands.html#set-account-quorum)
- [x] [subtractAssetQuantity](https://iroha.readthedocs.io/en/main/develop/api/commands.html#subtract-asset-quantity)
- [x] [transferAsset](https://iroha.readthedocs.io/en/main/develop/api/commands.html#transfer-asset)
- [x] [сompareAndSetAccountDetail](https://iroha.readthedocs.io/en/main/develop/api/commands.html#compare-and-set-account-detail)
- [x] [removePeer](https://iroha.readthedocs.io/en/main/develop/api/commands.html#remove-peer)


## Queries

- [x] [getAccount](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-account)
- [x] [getAccountAssetTransactions](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-account-asset-transactions)queries.html#get-account-assets)
- [x] [getAccountDetail](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-account-detail)
- [x] [getAccountTransactions](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-account-transactions)
- [x] [getTransactions](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-transactions)
- [x] [getSignatories](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-signatories)
- [x] [getAssetInfo](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-asset-info)
- [x] [getRoles](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-roles)
- [x] [getRolePermissions](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-role-permissions)
- [x] [getPeers](https://iroha.readthedocs.io/en/main/develop/api/queries.html#get-peers)


## Compatibility and release policy

The `develop` branch is compatible with tagged releases of Iroha.
