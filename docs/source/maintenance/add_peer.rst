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
2. Create another peer running HL Iroha with the same genesis block and similar configuration;
3. Send a transaction from the account with ``root`` permission that has ``add peer`` command in it (see an example below)
4. Check the logs of the peers to see if everything is working correctly.
You can also make sure the everything is ok by sending a transaction and checking if the number of blocks is the same on the nodes.

.. note:: If there are only 1 existing peer running, you will need to configure the peers that you are adding so that they would have all of the peers (both already existing and the new ones) in the "initial_peers" parameter in the `configuration <../configure/index.html#environment-specific-parameters>`_. If you have more than 2f+1 peers, this step is not needed, as the consensus will work without it.

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