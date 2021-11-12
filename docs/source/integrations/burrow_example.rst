Examples of How to Use HL Burrow EVM
====================================

This section demonstrates a few examples of how one can deploy and run smart contracts in an EVM on top of Iroha blockchain.

To interact with Iroha, we will be using a `Python Iroha client <https://iroha.readthedocs.io/en/main/getting_started/python-guide.html>`_. Assuming Iroha node is listening on a local port 50051, the client code will look something like:

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
For that we can either use the full-fledged Solidity compiler or the Web-based `Remix IDE <https://remix.ethereum.org>`_ .

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
	    iroha.command('CallEngine', caller='admin@test', input=bytecode)
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
	params = ("40c10f19”                                                          # selector
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


Case 2. Interacting with Iroha state
------------------------------------

Earlier we looked at an example of a contract that didn’t interact with Iroha state.
However, in most real life applications one could imagine running on top of Iroha blockchain (like custom business logic in transaction processing or charging transaction fees etc.) being able to interact with Iroha state is indispensable.
In this section we will consider an example of how one can query balances of Iroha accounts (provided the query creator has respective permissions) from inside an EVM smart contract.


Here is a sample code of contact to do so:

.. code-block:: solidity

	contract Iroha {
		address public serviceContractAddress;

		event Created(string indexed name, string indexed domain);
		event Transferred(string indexed source, string indexed destination, string amount);
		event Added(string indexed asset, string amount);


		// Initializing service contract address in constructor
		constructor(){
			serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
		}

		// Creates an iroha ccount
		function createAccount(string memory name, string memory domain, string memory key) public  returns (bytes memory result) {
			bytes memory payload = abi.encodeWithSignature(
				"createAccount(string,string,string)",
				name,
				domain,
				key);
			(bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
			require(success, "Error calling service contract function");
			emit Created(name, domain);
			result = ret;
		}

		//Transfers asset from one iroha account to another
		function transferAsset(string memory src, string memory dst, string memory asset, string memory description, string memory amount) public returns (bytes memory result) {
			bytes memory payload = abi.encodeWithSignature(
				"transferAsset(string,string,string,string,string)",
				src,
				dst,
				asset,
				description,
				amount);
			(bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
			require(success, "Error calling service contract function");

			emit Transferred(src, dst, amount);
			result = ret;
		}
		// Adds asset to iroha account
		function addAsset(string memory asset, string memory amount) public returns (bytes memory result) {
			bytes memory payload = abi.encodeWithSignature(
				"addAsset(string,string)",
				asset,
				amount);
			(bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
			require(success, "Error calling service contract function");

			emit Added(asset, amount);
			result = ret;
		}
		//Queries balance of an iroha account
		function queryBalance(string memory _account, string memory _asset) public returns (bytes memory result) {
			bytes memory payload = abi.encodeWithSignature(
				"getAssetBalance(string,string)",
				_account,
				_asset);
			(bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
			require(success,"Error calling service contract function ");
			result = ret;
		}
	}

In the constructor we initialize the EVM address of the `ServiceContract <burrow.html#running-native-iroha-commands-in-evm>`_ which exposes multiple APIs to interact with Iroha state.
These APIs can be used to query as well as modify the Iroha state. Most of the Iroha commands and queries have been integrated.
This contract calls the *getAssetBalance*, *createAccount*, *addAsset* and *transferAsset* methods of the Iroha *ServiceContract* API.

We need to compile the contract above to get the bytecode using a full-fledged Solidity compiler or the Web-based *Remix IDE*.
Now, we can send transactions from the Python Iroha client to deploy the contract to the EVM and also to call the different functions of the contact.
The contract is deployed in a similar manner as shown above. To call a function of the deployed contract, function signature and it's arguments must be encoded following the `ABI-specification <https://solidity.readthedocs.io/en/v0.6.5/abi-spec.html>`_.

Here is a sample python code that calls a function of a deployed contract:

.. code-block:: python

	def add_asset(address):
		params = get_first_four_bytes_of_keccak(
			b"addAsset(string,string)"
		)
		no_of_param = 2
		for x in range(no_of_param):
			params = params + left_padded_address_of_param(
				x, no_of_param
			)
		params = params + argument_encoding("coin#test")  # asset id
		params = params + argument_encoding("500")  # amount of asset
		tx = iroha.transaction(
			[
				iroha.command("CallEngine", caller=ADMIN_ACCOUNT_ID, callee=address, input=params)
			]
		)
		IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
		response = net.send_tx(tx)
		for status in net.tx_status_stream(tx):
			print(status)

	def make_number_hex_left_padded(number: str, width: int = 64):
		number_hex = "{:x}".format(number)
		return str(number_hex).zfill(width)


	def left_padded_address_of_param(param_index: int, number_of_params: int, width: int = 64):
		"""Specifies the position of each argument according to Contract ABI specifications."""
		bits_offset = 32 * number_of_params
		bits_per_param = 64
		bits_for_the_param = bits_offset + bits_per_param * param_index
		return make_number_hex_left_padded(bits_for_the_param, width)


	def argument_encoding(arg):
		"""Encodes the argument according to Contract ABI specifications."""
		encoded_argument = str(hex(len(arg)))[2:].zfill(64)
		encoded_argument = (
			encoded_argument + arg.encode("utf8").hex().ljust(64, "0").upper()
		)
		return encoded_argument


	def get_first_four_bytes_of_keccak(function_signature: str):
		"""Generates the first 4 bytes of the keccak256 hash of the function signature. """
		k = keccak.new(digest_bits=256)
		k.update(function_signature)
		return k.hexdigest()[:8]

An argument of type string, a dynamic type, is encoded in the following way:
First we provide the location part of the argument measured in bytes from the start of the arguments block which is then, left padded to 32 bytes. The data part of the argument starts with the length of the byte array in elements, also left padded to 32 bytes. Then UTF-8 encoding of the string, padded on the right to 32 bytes.
This can be achieved with the help of functions in the example.

For more examples and how the code works, you can visit `here  <https://github.com/hyperledger/iroha/tree/main/example/burrow_integration>`_ .
