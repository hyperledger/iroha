============
Adding Peers
============

In HL Iroha, you can add new peers to the network while it is running.
This is done by using a special command, `AddPeer <../develop/api/commands.html#add-peer>`_.

Requirements
============

**There should be a peer that:**

— runs with a Genesis Block (initial block of the blockchain) identical to the one on the peers already in the network;

— has a resolvable address;

— has a peer keypair (Ed25519 with SHA-3)

**The account that is sending the transaction adding a peer must have a `root permission <../develop/api/permissions.html#root>`_ in their role - this must be set in the genesis block.**

Usage
=====

As described in `the API reference <../develop/api/commands.html#add-peer>`_ to use the command, you will only need:

— a public key of the peer that you want to add to the network;

— resolvable IP address of the peer

Steps:

1. Create a network with ``root`` permission set up in the genesis block assigned to a user;
2. Create another peer running HL Iroha with the same genesis block
3. Send a transaction from the account with ``root`` permission that has ``add peer`` command in it (see an example below)
4. Check the logs of the peers to see it everything is working correctly.

Example
=======

Here is what a command might look like in Python:

.. code-block:: python

	def add_peer():
    	peer1 = primitive_pb2.Peer()
    	peer1.address = '192.168.1.1:50541'
    	peer1.peer_key = '716fe505f69f18511a1b083915aa9ff73ef36e6688199f3959750db38b8f4bfc'
    	tx = iroha.transaction([
        	iroha.command('AddPeer', peer=peer1)
    	], creator_account=ADMIN_ACCOUNT_ID, quorum=1)

    	IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
	add_peer()

Remove Peer
===========

To remove the peer, you will need to use `Remove Peer <../develop/api/commands.html#remove-peer>`_ command from the account that has ``CanRemovePeer permission``.