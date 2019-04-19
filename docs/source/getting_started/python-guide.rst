Sending transactions with Python library
========================================

Prerequisites
-------------

.. note:: the library only works in Python 3 environment (Python 2 is not supported yet).

To use Iroha Python library, you need to get it from the `repository <https://github.com/hyperledger/iroha-python>`_ or via pip3: 

.. code-block:: shell

	pip3 install iroha

Now, as we have the library, we can start sending the actual transactions. 

Running example transactions
----------------------------

If you only want to try what Iroha transactions would look like, you can simply go to the examples from the repository `here <https://github.com/hyperledger/iroha-python/tree/master/examples>`_. 
Let's check out the `tx-example.py` file. 

Here are Iroha dependencies. Python library generally consists of 3 parts: Iroha, IrohaCrypto and IrohaGrpc which we need to import: 

.. code-block:: python

	from iroha import Iroha, IrohaGrpc
	from iroha import IrohaCrypto

The line 

.. code-block:: python

	from iroha.primitive_pb2 import can_set_my_account_detail


is actually about the permissions you might be using for the transaction. 
You can find a full list here: ref:`Permissions`. 


In the next block we can see the following: 

.. code-block:: python

	admin_private_key = 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70'
	user_private_key = IrohaCrypto.private_key()
	user_public_key = IrohaCrypto.derive_public_key(user_private_key)
	iroha = Iroha('admin@test')
	net = IrohaGrpc()

Here you can see the example account information. It will be used later with the commands. 
If you change the commands in the transaction, the set of data in this part might also change depending on what you need.

Defining the commands
---------------------

Let's look at the first of the difined commands: 

.. code-block:: python

	def create_domain_and_asset():
	    commands = [
	        iroha.command('CreateDomain', domain_id='domain', default_role='user'),
	        iroha.command('CreateAsset', asset_name='coin',
	                      domain_id='domain', precision=2)
	    ]
	    tx = IrohaCrypto.sign_transaction(
	        iroha.transaction(commands), admin_private_key)
	    send_transaction_and_print_status(tx)

Here we define a transaction made of 2 commands: CreateDomain and CreateAsset. 
You can find a full list here: ref:`commands`.
Each of Iroha commands has its own set of parameters. 
You can check them in command descriptions in ref:`iroha-api-reference`. 

Then we sign the transaction with the parameters defined earlier. 

You can define ref:`queries` the same way. 

Running the commands
--------------------

Last lines 

.. code-block:: python

	create_domain_and_asset()
	add_coin_to_admin()
	create_account_userone()
	...

run the commands defined previously. 

Now, if you have `irohad` running, you can run the example or you own file by simply opening the .py file in another tab.  


