Examples of How to Use HL Burrow EVM
====================================

This section demonstrates a few examples of how one can deploy and run smart contracts in an EVM on top of Iroha blockchain.

To interact with Iroha, we will be using a `Python Iroha client <https://iroha.readthedocs.io/en/master/getting_started/python-guide.html>`_. Assuming Iroha node is listening on a local port 50051, the client code will look something like:

.. code-block:: python

	import os
	from iroha import Iroha, IrohaCrypto, IrohaGrpc

	iroha = Iroha('admin@test')
	net = IrohaGrpc('127.0.0.1:50051')

	admin_key = os.getenv(ADMIN_PRIVATE_KEY, IrohaCrypto.private_key())
	# Code for preparing and sending transaction

Case 1. Running computations and storing data
---------------------------------------------

As the first example we will take the `Subcurrency <https://solidity.readthedocs.io/en/latest/introduction-to-smart-contracts.html#subcurrency-example>`_ smart contract from the Solidity documentation.
The contract code is the following (the reader may refer to the original documentation to understand what each line of the contract code means, if necessary):

.. code-block:: solidity

    contract Coin {
        // The keyword "public" makes variables
        // accessible from other contracts
        address public minter;
        mapping (address => uint) public balances;

        // Events allow clients to react to specific
        // contract changes you declare
        event Sent(address from, address to, uint amount);

        // Constructor code is only run when the contract
        // is created
        constructor() public {
            minter = msg.sender;
        }

        // Sends an amount of newly created coins to an address
        // Can only be called by the contract creator
        function mint(address receiver, uint amount) public {
            require(msg.sender == minter);
            require(amount < 1e60);
            balances[receiver] += amount;
        }

        // Sends an amount of existing coins
        // from any caller to an address
        function send(address receiver, uint amount) public {
            require(amount <= balances[msg.sender], "Insufficient balance.");
            balances[msg.sender] -= amount;
            balances[receiver] += amount;
            emit Sent(msg.sender, receiver, amount);
        }
    }

To start off, we need to compile the source code above to the bytecode.
For that we can either use the full-fledged Solidity compiler or the Web-based *Remix IDE*.
Having got the bytecode, we can now send a  transaction from the Python Iroha client which will deploy the contract to the EVM:

.. code-block:: python

	import os
	from iroha import Iroha, IrohaCrypto, IrohaGrpc

	iroha = Iroha('admin@test')
	net = IrohaGrpc('127.0.0.1:50051')

	admin_key = os.getenv(ADMIN_PRIVATE_KEY, IrohaCrypto.private_key())
	bytecode = ("608060405234801561001057600080fd5b50336000806101000a81548173ffff”
	            "ffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffff"
	            ...
	            "030033")

	tx = iroha.transaction([
	    iroha.command('CallEngine', caller='admin@energy', input=bytecode)
	])
	IrohaCrypto.sign_transaction(tx, admin_key)

	net.send_tx(tx)
	for status in net.tx_status_stream(tx):
	    print(status)


To call the mint method of this contract, we send the same *CallEngine* command with the input parameter containing the method selector - the first 4 bytes of the *keccak256* hash of the function signature:

``keccak256(‘mint(address,uint256)’) == ‘40c10f19’``

concatenated with the function arguments encoded according to the contract ABI rules – the first function argument has the *address* type, that is a 20-bytes long integer number.

Let’s say the contract owner (the *admin@test* Iroha account) wants to mint 1000 coins and assign them to himself.
To get the EVM address corresponding to the *admin@test* using Python library we might use:

.. code-block:: python

	import sha3
	k = sha3.keccak_256()
	k.update(b'admin@test')
	print(hexlify(k.digest()[12:32]).zfill(64))

That way, we'll get:

``000000000000000000000000f205c4a929072dd6e7fc081c2a78dbc79c76070b``

So, the last 20 bytes are keccak256, zero left-padded to 32 bytes.


The *amount* argument is a *uint256* number encoded in hex (also, left-padded):

``00000000000000000000000000000000000000000000000000000000000003e8``

The entire arguments string is a concatenation of the three pieces above chained together.


Putting it all together, we will get the following client code to call the *mint* function of the *Coin* contract:

.. code-block:: python

	import os
	from iroha import Iroha, IrohaCrypto, IrohaGrpc

	iroha = Iroha('admin@test')
	net = IrohaGrpc('127.0.0.1:50051')

	admin_key = os.getenv(ADMIN_PRIVATE_KEY, IrohaCrypto.private_key())
	params = ("40c10f19”                                                             # selector
	          "000000000000000000000000f205c4a929072dd6e7fc081c2a78dbc79c76070b"  # address
	          "00000000000000000000000000000000000000000000000000000000000003e8"  # amount
	         )

	tx = iroha.transaction([
	    iroha.command('CallEngine', callee='ServiceContract', input=params)
	])
	IrohaCrypto.sign_transaction(tx, admin_key)

	net.send_tx(tx)
	for status in net.tx_status_stream(tx):
	    print(status)

Calling the *send* function is done in exactly the same way.

Note the last line of the send function that emits a Sent event which gets recorded in the log as described earlier:

.. code-block:: solidity

	emit Sent(msg.sender, receiver, amount);


Case 2. Querying Iroha state
----------------------------

Earlier we looked at an example of a contract that didn’t interact with Iroha state.
However, in most real life applications one could imagine running on top of Iroha blockchain (like custom business logic in transaction processing or charging transaction fees etc.) being able to interact with Iroha state is indispensable.
In this section we will consider an example of how one can query balances of Iroha accounts (provided the query creator has respective permissions) from inside an EVM smart contract.


The code of the contract is presented on the diagram below:

.. code-block:: solidity

	contract QueryIroha {
	    address public serviceContractAddress;

	    // Initializing service contract address in constructor
	    constructor() public {
	        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
	    }

	    // Queries the balance in _asset of an Iroha _account
	    function queryBalance(string memory _account, string memory _asset) public
	                    returns (bytes memory result) {
	        bytes memory payload = abi.encodeWithSignature(
	            "getAssetBalance(string,string)",
	            _account,
	            _asset);
	        (bool success, bytes memory ret) =
	            address(serviceContractAddress).delegatecall(payload);
	        require(success, "Error calling service contract function");
	        result = ret;
	    }
	}

In the constructor we initialize the EVM address of the `ServiceContract <burrow.html#running-native-iroha-commands-in-evm>`_ which exposes an API to interact with Iroha state.
The contract function *queryBalance* calls the *getAssetBalance* method of the Iroha *ServiceContract* API.

Case 3. Changing Iroha state
----------------------------

The final example we consider here is a transfer of an asset from one Iroha account to another.


The contract code is as follows:

.. code-block:: solidity

	contract Transfer {
	    address public serviceContractAddress;

	    event Transferred(string indexed source, string indexed destination, string amount);

	    // Initializing service contract address in constructor
	    constructor() public {
	        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
	    }

	    // Queries the balance in _asset of an Iroha _account
	    function transferAsset(string memory src, string memory dst,
	                           string memory asset, string memory amount) public
	                    returns (bytes memory result) {
	        bytes memory payload = abi.encodeWithSignature(
	            "transferAsset(string,string,string,string)",
	            src,
	            dst,
	            asset,
	            amount);
	        (bool success, bytes memory ret) =
	            address(serviceContractAddress).delegatecall(payload);
	        require(success, "Error calling service contract function");

	        emit Transferred(src, dst, amount);
	        result = ret;
	    }
	}


Similarly to querying Iroha state, a command can be sent to modify  the latter.
In the example above the API method *transferAssetBalance* of the `ServiceContract <burrow.html#running-native-iroha-commands-in-evm>`_ sends some *amount* of the *asset* from Iroha account *src* to the account *dst*. Of course, if the transaction creator has sufficient permissions to execute this operation.








