HL Burrow Integration
=====================

As Iroha maintainers, we have received many questions and requests for custom smart-contracts support from our users.
And to provide them more freedom in fulfilling their business needs, we integrated HL Burrow EVM – another great project of the Hyperledger greenhouse, – into Iroha.

.. note:: In the context of Iroha, HL Burrow provides an Ethereum Virtual Machine that can run Solidity smart-contracts.
	We did our best to provide you with the best user experience possible – and to use it with Iroha, you only need to add a `CMake flag during Iroha build <../build/index.html#cmake-parameters>`_ and it will start working right away.

You can read about Solidity smart-contract language `here <https://solidity.readthedocs.io/>`_, if you are new to this language.

How it works
------------

For this integration, we have created a special `Call Engine command <../develop/api/commands.html#call-engine>`_ in Iroha, as well as a special `Engine Receipts query <../develop/api/queries.html#engine-receipts>`_ for retrieving the results of the command.

The command
^^^^^^^^^^^

In the command, you can:

**Сreate a new contract account in EVM**

If the *callee* in the `CallEngine <../develop/api/commands.html#call-engine>`_ is not specified and the *input* parameter contains some bytecode, a new contract account is created.

**Call a method of a previously deployed contract**

If the *callee* is specified, then the input is treated as an ABI-encoded selector of a method of the callee contract followed by the arguments.

.. hint:: It is much like deploying a contract or calling a contract function in Ethereum depending on the contents of the `data` field of the `eth_sendTransaction <https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sendtransaction>`_ message call.
	See `ABI-specification <https://solidity.readthedocs.io/en/v0.6.5/abi-spec.html>`_ for details.

The query
^^^^^^^^^

To query the outcome of a `CallEngine <../develop/api/commands.html#call-engine>`_ command one should use the `Engine Receipts query <../develop/api/queries.html#engine-receipts>`_.
The output of any computations inside the EVM will not be available for the caller until it has been written to the ledger (that is, the block that has the respective Iroha transaction has been committed).
Among the other `data <../develop/api/queries.html#response-structure>`_, the *EngineReceipts* query will return an array of log entries generated in the EVM during the *CallEngine* execution.

.. hint:: A common way for dApps developers to let interested parties see the outcome of a contract execution is to emit an event with some data before exiting a contract function so that this data is written to the *Event Log*.
	`Ethereum Yellow Paper <https://ethereum.github.io/yellowpaper/paper.pdf>`_ defines a log entry as a 3-tuple containing the emitter’s address, an array of 32-byte long topics and a byte array of some data.

Running Native Iroha Commands in EVM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With HL Burrow integration, you can also use native commands to change the state of Iroha.

The integration mechanism of Burrow EVM empowers Iroha application developers with a tool able to directly act on the Iroha state from smart contracts code thus providing foundation for programmable business logic extensions of the built-in Iroha commands system.
Conditional asset transfers, transaction fees, non-fungible assets and so on are just a few examples of such extensions.
The tricky part here is that the Iroha data model is quite different from that of Ethereum.
For instance, in Ethereum there is only one kind of built-in asset (`Eth`) therefore getting an account balance in EVM context simply means returning the balance property of the account.
In Iroha, on the other hand, an account can have multiple assets, or not have assets at all, so any function that returns an account balance must take at least one extra argument – the asset ID.
Same logic applies to transferring/sending assets from account to account.

As a solution to this data model mismatch problem we introduce so-called Service Contracts in Burrow that are “aware” of the Iroha data model and expose an API to interact with Iroha state (query balances, transfer assets and so on).
From the Burrow EVM perspective such Service Contract is hosted in a Native external VM and is callable via the same interfaces as if it was deployed at some special address in the EVM itself.

.. note:: You can check out `Burrow documentation <https://wiki.hyperledger.org/display/burrow/Burrow+-+The+Boring+Blockchain>`_ for more information on Natives and external dispatchers.

Schematically the interaction between different parts of the system looks as follows:

.. image:: ../../image_assets/burrow/natives.png

Current release of the Iroha EVM wrapper contains a single service contract deployed at the address `A6ABC17819738299B3B2C1CE46D55C74F04E290C` (the last 20 bytes of the *keccak256* hash of the string *ServiceContract*) which exposes 2 methods to query Iroha assets balances and transfer assets between accounts.
The signature of these four method looks like this:

	**function** getAssetBalance(string memory *accountID*, string memory *assetID*) public view
	returns (string memory *result*) {}

	**function** transferAsset(string memory *src*, string memory *dst*, string memory *assetID*,
	string memory *amount*) public view returns (string memory *result*) {}

.. hint:: From a developer’s perspective calling a function of a native contract is no different from calling a method of any other smart contract provided the address of the latter is known:

	bytes memory payload = abi.encodeWithSignature("getOtherAssetBalance(string,string)", "myacc@test", "coin#test");

	(bool success, bytes memory ret) = address(0xA6ABC17819738299B3B2C1CE46D55C74F04E290C).delegatecall(payload);

Here a special kind of EVM message calls is used - the **delegatecall**, which allows a contract to dynamically load and run code from a different address at runtime in its own execution context.

.. seealso:: Now, let's move to the usage `examples <burrow_example.html>`_










