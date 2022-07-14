Sending Transactions With Python library
========================================

Open a new terminal (note that Iroha container and ``irohad`` should be up and
running) and attach to an ``iroha`` docker container:

.. code-block:: shell

  docker exec -it iroha /bin/bash

Now you are in the interactive shell of Iroha's container.

Prerequisites
-------------

.. note:: The library only works in Python 3 environment (Python 2 is not supported).

To use Iroha Python library, you need to get it from the
`repository <https://github.com/hyperledger/iroha-python>`_ or via pip3:

.. code-block:: shell

	pip3 install iroha

Creating your own key pairs with Python library
-----------------------------------------------

For testing purposes, you can use example keys.
But you can also create your own.
To create **native Iroha ed25519 SHA-3** keys (difference between algorithms can be found `here <../develop/keys.html>`__), please use the following code:

.. code-block:: python

	from iroha import IrohaCrypto

	# these first two lines are enough to create the keys
	private_key = IrohaCrypto.private_key()
	public_key = IrohaCrypto.derive_public_key(private_key)

	# the rest of the code writes them into the file
	with open('keypair.priv', 'wb') as f:
	    f.write(private_key)

	with open('keypair.pub', 'wb') as f:
	    f.write(public_key)

And for HL Ursa ed25519 SHA-2 keys in Multihash format, please use:

.. code-block:: python

	from iroha import IrohaCrypto, ed25519_sha2
	from nacl.encoding import HexEncoder

	private_key = ed25519_sha2.SigningKey.generate()
	public_key = IrohaCrypto.derive_public_key(private_key).encode('ascii')

	with open('keypair.priv', 'wb') as f:
	    f.write(private_key.encode(encoder=HexEncoder))
	    f.write(public_key[6:])

	with open('keypair.pub', 'wb') as f:
	    f.write(public_key)


Now, as we have the library and the keys, we can start sending the actual transactions.

Running example transactions
----------------------------

If you only want to try what Iroha transactions would look like,
you can simply go to the examples from the repository
`here <https://github.com/hyperledger/iroha-python/tree/master/examples>`_.
Here is the `tx-example.py` file with comments to clarify each step:

.. remoteliteralinclude:: https://raw.githubusercontent.com/hyperledger/iroha-python/master/examples/tx-example.py
   :language: python


Now, if you have `irohad` running, you can run the example or
your own file by simply opening the .py file in another tab.

.. note:: There are more samples in the `iroha-python examples directory <https://github.com/hyperledger/iroha-python/tree/main/examples>`_.
