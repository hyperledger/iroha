Commands
========

A command changes the state, called World State View, by performing an action over an entity (asset, account) in the system.
Any command should be included in a transaction to perform an action.

Add asset quantity
------------------

Purpose
^^^^^^^

The purpose of add asset quantity command is to increase the quantity of an asset on account of transaction creator.
Use case scenario is to increase the number of a mutable asset in the system, which can act as a claim on a commodity (e.g. money, gold, etc.)

Schema
^^^^^^

.. code-block:: proto

    message AddAssetQuantity {
        string asset_id = 1;
        string amount = 2;
        optional string description = 3;
    }

.. note::
    Please note that due to a known issue you would not get any exception if you pass invalid precision value.
    Valid range is: 0 <= precision <= 255


Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Asset ID", "id of the asset", "<asset_name>#<domain_id>", "usd#morgan"
    "Amount", "positive amount of the asset to add", "> 0", "200.02"
    "Description", "description of the transaction", "Max length of description (set in genesis block, by default is 100*1024)", "Mint assets"

Validation
^^^^^^^^^^

1. Asset and account should exist
2. Added quantity precision should be equal to asset precision
3. Creator of a transaction should have a role which has permissions for issuing assets

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not add asset quantity", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to add asset quantity", "Grant the necessary permission"
    "3", "No such asset", "Cannot find asset with such name or such precision", "Make sure asset id and precision are correct"
    "4", "Summation overflow", "Resulting asset quantity is greater than the system can support", "Make sure that resulting quantity is less than 2^256 / 10^asset_precision"

Add peer
--------

Purpose
^^^^^^^

The purpose of add peer command is to write into ledger the fact of peer addition into the peer network.
After a transaction with AddPeer has been committed, consensus and synchronization components will start using it.
You can also `learn more about Add Peer command <../../maintenance/add_peer.html>`_.

Schema
^^^^^^

.. literalinclude:: ../../../../shared_model/schema/primitive.proto
    :language: proto
    :start-at: message Peer {
    :end-before: message AccountDetailRecordId {
    
.. code-block:: proto

    message AddPeer {
        Peer peer = 1;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 10, 30

    "Address", "resolvable address in network (IPv4, IPv6, domain name, etc.)", "should be resolvable", "192.168.1.1:50541"
    "Peer key", "peer public key, which is used in consensus algorithm to sign-off vote, commit, reject messages", "ed25519 public key", "292a8714694095edce6be799398ed5d6244cd7be37eb813106b217d850d261f2"

Validation
^^^^^^^^^^

1. Peer key is unique (there is no other peer with such public key)
2. Creator of the transaction has a role which has CanAddPeer permission
3. Such network address has not been already added

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not add peer", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to add peer", "Grant the necessary permission"

Add signatory
-------------

Purpose
^^^^^^^

The purpose of add signatory command is to add an identifier to the account.
Such identifier is a public key of another device or a public key of another user.

Schema
^^^^^^

.. code-block:: proto

    message AddSignatory {
        string account_id = 1;
        bytes public_key = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "Account to which to add signatory", "<account_name>@<domain_id>", "makoto@soramitsu"
    "Public key", "Signatory to add to account", "ed25519 public key", "359f925e4eeecfdd6aa1abc0b79a6a121a5dd63bb612b603247ea4f8ad160156"

Validation
^^^^^^^^^^

Two cases:

    Case 1. Transaction creator wants to add a signatory to his or her account, having permission CanAddSignatory

    Case 2. CanAddSignatory was granted to transaction creator

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not add signatory", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to add signatory", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to add signatory to", "Make sure account id is correct"
    "4", "Signatory already exists", "Account already has such signatory attached", "Choose another signatory"

Append role
-----------

Purpose
^^^^^^^

The purpose of append role command is to promote an account to some created role in the system, where a role is a set of permissions account has to perform an action (command or query).

Schema
^^^^^^

.. code-block:: proto

    message AppendRole {
       string account_id = 1;
       string role_name = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "id or account to append role to", "already existent", "makoto@soramitsu"
    "Role name", "name of already created role", "already existent", "MoneyCreator"

Validation
^^^^^^^^^^

1. The role should exist in the system
2. Transaction creator should have permissions to append role (CanAppendRole)
3. Account, which appends role, has set of permissions in his roles that is a superset of appended role (in other words no-one can append role that is more powerful than what transaction creator is)

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not append role", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to append role", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to append role to", "Make sure account id is correct"
    "4", "No such role", "Cannot find role with such name", "Make sure role id is correct"

Call engine
-----------

Purpose
^^^^^^^

The purpose of call engine command is to deploy a new contract to the Iroha EVM or to call a method of an already existing smart contract.
An execution of a smart contract can potentially modify the state of the ledger provided the transaction that contains this command is accepted to a block and the block is committed.

Schema
^^^^^^

.. code-block:: proto

    message CallEngine {
        string caller = 1;
        oneof opt_callee {
            string callee = 2;  // hex string
        }
        string input = 3;   // hex string
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"

    "Caller", "Iroha account ID of an account on whose behalf the command is run", "<account_name>@<domain_id>", "test@mydomain"
    "Callee", "the EVM address of a deployed smart contract", "20-bytes string in hex representation", "7C370993FD90AF204FD582004E2E54E6A94F2651"
    "Input", "Bytecode of a smart contract for a newly deployed contracts or ABI-encoded string of the contract method selector followed by the `set of its arguments <https://solidity.readthedocs.io/en/v0.6.5/abi-spec.html>`_", "Hex string", "40c10f19000000000000000000000000969453762b0c739dd285b31635efa00e24c2562800000000000000000000000000000000000000000000000000000000000004d2"

Validation
^^^^^^^^^^

1. Caller is a valid Iroha account ID
2. The transaction creator has a role with either can_call_engine or can_call_engine_on_my_behalf permission

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Engine is not configured", "This error means that Iroha was built without Burrow EVM", "See `Build <../../build/index.html#main-parameters>`_ section of documentation to build Iroha correctly"
    "2", "No such permissions", "Command’s creator does not have a permission to call EVM engine", "Grant the necessary permission"
    "3", "CallEngine error", "Code execution in EVM failed; the reason can be both in the contract code itself or be rooted in nested Iroha commands call", "Investigation of the error root cause is required in order to diagnose the issue"

Create account
--------------

Purpose
^^^^^^^

The purpose of create account command is to make entity in the system, capable of sending transactions or queries, storing signatories, personal data and identifiers.

Schema
^^^^^^

.. code-block:: proto

    message CreateAccount {
        string account_name = 1;
        string domain_id = 2;
        bytes public_key = 3;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account name", "domain-unique name for account", "`[a-z_0-9]{1,32}`", "morgan_stanley"
    "Domain ID", "target domain to make relation with", "should be created before the account", "america"
    "Public key", "first public key to add to the account", "ed25519 public key", "407e57f50ca48969b08ba948171bb2435e035d82cec417e18e4a38f5fb113f83"

Validation
^^^^^^^^^^

1. Transaction creator has permission to create an account
2. Domain, passed as domain_id, has already been created in the system
3. Such public key has not been added before as first public key of account or added to a multi-signature account

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not create account", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator either does not have permission to create account or tries to create account in a more privileged domain, than the one creator is in", "Grant the necessary permission or choose another domain"
    "3", "No such domain", "Cannot find domain with such name", "Make sure domain id is correct"
    "4", "Account already exists", "Account with such name already exists in that domain", "Choose another name"

Create asset
------------

Purpose
^^^^^^^

The purpose of сreate asset command is to create a new type of asset, unique in a domain.
An asset is a countable representation of a commodity.

Schema
^^^^^^

.. code-block:: proto

    message CreateAsset {
        string asset_name = 1;
        string domain_id = 2;
        uint32 precision = 3;
    }

.. note::
    Please note that due to a known issue you would not get any exception if you pass invalid precision value.
    Valid range is: 0 <= precision <= 255

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Asset name", "domain-unique name for asset", "`[a-z_0-9]{1,32}`", "soracoin"
    "Domain ID", "target domain to make relation with", "RFC1035 [#f1]_, RFC1123 [#f2]_", "japan"
    "Precision", "number of digits after comma/dot", "0 <= precision <= 255", "2"

Validation
^^^^^^^^^^

1. Transaction creator has permission to create assets
2. Asset name is unique in domain

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not create asset", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to create asset", "Grant the necessary permission"
    "3", "No such domain", "Cannot find domain with such name", "Make sure domain id is correct"
    "4", "Asset already exists", "Asset with such name already exists", "Choose another name"

Create domain
-------------

Purpose
^^^^^^^

The purpose of create domain command is to make new domain in Iroha network, which is a group of accounts.

Schema
^^^^^^

.. code-block:: proto

    message CreateDomain {
        string domain_id = 1;
        string default_role = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Domain ID", "ID for created domain", "unique, RFC1035 [#f1]_, RFC1123 [#f2]_", "japan05"
    "Default role", "role for any created user in the domain", "one of the existing roles", "User"

Validation
^^^^^^^^^^

1. Domain ID is unique
2. Account, who sends this command in transaction, has role with permission to create domain
3. Role, which will be assigned to created user by default, exists in the system

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not create domain", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to create domain", "Grant the necessary permission"
    "3", "Domain already exists", "Domain with such name already exists", "Choose another domain name"
    "4", "No default role found", "Role, which is provided as a default one for the domain, is not found", "Make sure the role you provided exists or create it"

Create role
-----------

Purpose
^^^^^^^

The purpose of create role command is to create a new role in the system from the set of permissions.
Combining different permissions into roles, maintainers of Iroha peer network can create customized security model.

Schema
^^^^^^

.. code-block:: proto

    message CreateRole {
        string role_name = 1;
        repeated RolePermission permissions = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Role name", "name of role to create", "`[a-z_0-9]{1,32}`", "User"
    "RolePermission", "array of already existent permissions", "set of passed permissions is fully included into set of existing permissions", "{can_receive, can_transfer}"

Validation
^^^^^^^^^^

1. Set of passed permissions is fully included into set of existing permissions
2. Set of the permissions is not empty

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not create role", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to create role", "Grant the necessary permission"
    "3", "Role already exists", "Role with such name already exists", "Choose another role name"

Detach role
-----------

Purpose
^^^^^^^

The purpose of detach role command is to detach a role from the set of roles of an account.
By executing this command it is possible to decrease the number of possible actions in the system for the user.

Schema
^^^^^^

.. code-block:: proto

    message DetachRole {
        string account_id = 1;
        string role_name = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "ID of account where role will be deleted", "already existent", "makoto@soramitsu"
    "Role name", "a detached role name", "existing role", "User"

Validation
^^^^^^^^^^

1. The role exists in the system
2. The account has such role

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not detach role", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to detach role", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to detach role from", "Make sure account id is correct"
    "4", "No such role in account's roles", "Account with such id does not have role with such name", "Make sure account-role pair is correct"
    "5", "No such role", "Role with such name does not exist", "Make sure role id is correct"

Grant permission
----------------

Purpose
^^^^^^^

The purpose of grant permission command is to give another account rights to perform actions on the account of transaction sender (give someone right to do something with my account).

Schema
^^^^^^

.. code-block:: proto

    message GrantPermission {
        string account_id = 1;
        GrantablePermission permission = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "id of the account to which the rights are granted", "already existent", "makoto@soramitsu"
    "GrantablePermission name", "name of grantable permission", "permission is defined", "CanTransferAssets"


Validation
^^^^^^^^^^

1. Account exists
2. Transaction creator is allowed to grant this permission

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not grant permission", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to grant permission", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to grant permission to", "Make sure account id is correct"

Remove peer
-----------

Purpose
^^^^^^^

The purpose of remove peer command is to write into ledger the fact of peer removal from the network.
After a transaction with RemovePeer has been committed, consensus and synchronization components will start using it.

Schema
^^^^^^

.. code-block:: proto

    message RemovePeer {
        bytes public_key = 1; // hex string
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 10, 30

    "Public key", "peer public key, which is used in consensus algorithm to sign vote messages", "ed25519 public key", "292a8714694095edce6be799398ed5d6244cd7be37eb813106b217d850d261f2"

Validation
^^^^^^^^^^

1. There is more than one peer in the network
2. Creator of the transaction has a role which has CanRemovePeer permission
3. Peer should have been previously added to the network

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not remove peer", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to remove peer", "Grant the necessary permission"
    "3", "No such peer", "Cannot find peer with such public key", "Make sure that the public key is correct"
    "4", "Network size does not allow to remove peer", "After removing the peer the network would be empty", "Make sure that the network has at least two peers"

Remove signatory
----------------

Purpose
^^^^^^^

Purpose of remove signatory command is to remove a public key, associated with an identity, from an account

Schema
^^^^^^

.. code-block:: proto

    message RemoveSignatory {
        string account_id = 1;
        bytes public_key = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "id of the account to which the rights are granted", "already existent", "makoto@soramitsu"
    "Public key", "Signatory to delete", "ed25519 public key", "407e57f50ca48969b08ba948171bb2435e035d82cec417e18e4a38f5fb113f83"

Validation
^^^^^^^^^^

1. When signatory is deleted, we should check if invariant of **size(signatories) >= quorum** holds
2. Signatory should have been previously added to the account

Two cases:

    Case 1. When transaction creator wants to remove signatory from their account and he or she has permission CanRemoveSignatory

    Case 2. CanRemoveSignatory was granted to transaction creator

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not remove signatory", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to remove signatory from his account", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to remove signatory from", "Make sure account id is correct"
    "4", "No such signatory", "Cannot find signatory with such public key", "Make sure public key is correct"
    "5", "Quorum does not allow to remove signatory", "After removing the signatory account will be left with less signatories, than its quorum allows", "Reduce the quorum"

Revoke permission
-----------------

Purpose
^^^^^^^

The purpose of revoke permission command is to revoke or dismiss given granted permission from another account in the network.

Schema
^^^^^^

.. code-block:: proto

    message RevokePermission {
        string account_id = 1;
        GrantablePermission permission = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: auto

        "Account ID", "id of the account to which the rights are granted", "already existent", "makoto@soramitsu"
        "GrantablePermission name", "name of grantable permission", "permission was granted", "CanTransferAssets"

Validation
^^^^^^^^^^

Transaction creator should have previously granted this permission to a target account

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not revoke permission", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to revoke permission", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to revoke permission from", "Make sure account id is correct"

Set account detail
------------------

Purpose
^^^^^^^

Purpose of set account detail command is to set key-value information for a given account

.. warning:: If there was a value for a given key already in the storage then it will be replaced with the new value

Schema
^^^^^^

.. code-block:: proto

    message SetAccountDetail{
        string account_id = 1;
        string key = 2;
        string value = 3;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "id of the account to which the key-value information was set", "already existent", "makoto@soramitsu"
    "Key", "key of information being set", "`[A-Za-z0-9_]{1,64}`", "Name"
    "Value", "value of corresponding key", "≤ 4096", "Makoto"

Validation
^^^^^^^^^^

Three cases:

    Case 1. When transaction creator wants to set account detail to other person's account and creator has permission `can_set_detail <../api/permissions.html#can-set-detail>`_.

    Case 2. `can_set_my_account_detail <../api/permissions.html#can-set-my-account-detail>`_ was granted to transaction creator in order to allow them to set account details of the target account.

    Case 3. When the account holder wants to set their own account details – no permission is needed in this case.

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not set account detail", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to set account detail for another account", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to set account detail to", "Make sure account id is correct"

Set account quorum
------------------

Purpose
^^^^^^^

The purpose of set account quorum command is to set the number of signatories required to confirm the identity of a user, who creates the transaction.
Use case scenario is to set the number of different users, utilizing single account, to sign off the transaction.

Schema
^^^^^^

.. code-block:: proto

    message SetAccountQuorum {
        string account_id = 1;
        uint32 quorum = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "ID of account to set quorum", "already existent", "makoto@soramitsu"
    "Quorum", "number of signatories needed to be included within a transaction from this account", "0 < quorum ≤ public-key set up to account ≤ 128", "5"

Validation
^^^^^^^^^^

When quorum is set, it is checked if invariant of **size(signatories) >= quorum** holds.

Two cases:

    Case 1. When transaction creator wants to set quorum for his/her account and he or she has permission CanRemoveSignatory

    Case 2. CanRemoveSignatory was granted to transaction creator

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not set quorum", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to set quorum for his account", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to set quorum to", "Make sure account id is correct"
    "4", "No signatories on account", "Cannot find any signatories attached to the account", "Add some signatories before setting quorum"
    "5", "New quorum is incorrect", "New quorum size is less than account's signatories amount", "Choose another value or add more signatories"

Subtract asset quantity
-----------------------

Purpose
^^^^^^^

The purpose of subtract asset quantity command is the opposite of AddAssetQuantity commands — to decrease the number of assets on account of transaction creator.

Schema
^^^^^^

.. code-block:: proto

    message SubtractAssetQuantity {
        string asset_id = 1;
        string amount = 2;
        optional string description = 3;
    }

.. note::
    Please note that due to a known issue you would not get any exception if you pass invalid precision value.
    Valid range is: 0 <= precision <= 255

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Asset ID", "id of the asset", "<asset_name>#<domain_id>", "usd#morgan"
    "Amount", "positive amount of the asset to subtract", "> 0", "200"
    "Description", "description of the transaction", "Max length of description (set in genesis block, by default is 100*1024)", "Burn assets"

Validation
^^^^^^^^^^

1. Asset and account should exist
2. Added quantity precision should be equal to asset precision
3. Creator of the transaction should have a role which has permissions for subtraction of assets

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not subtract asset quantity", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to subtract asset quantity", "Grant the necessary permission"
    "3", "No such asset found", "Cannot find asset with such name or precision in account's assets", "Make sure asset name and precision are correct"
    "4", "Not enough balance", "Account's balance is too low to perform the operation", "Add asset to account or choose lower value to subtract"

Transfer asset
--------------

Purpose
^^^^^^^

The purpose of transfer asset command is to share assets within the account in peer network: in the way that source account transfers assets to the target account.

Schema
^^^^^^

.. code-block:: proto

    message TransferAsset {
        string src_account_id = 1;
        string dest_account_id = 2;
        string asset_id = 3;
        string description = 4;
        string amount = 5;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Source account ID", "ID of the account to withdraw the asset from", "already existent", "makoto@soramitsu"
    "Destination account ID", "ID of the account to send the asset to", "already existent", "alex@california"
    "Asset ID", "ID of the asset to transfer", "already existent", "usd#usa"
    "Description", "Message to attach to the transfer", "Max length of description (set in genesis block, by default is 100*1024)", "here's my money take it"
    "Amount", "amount of the asset to transfer", "0 <= precision <= 255", "200.20"

Validation
^^^^^^^^^^

1. Source account has this asset in its AccountHasAsset relation [#f1]_
2. An amount is a positive number and asset precision is consistent with the asset definition
3. Source account has enough amount of asset to transfer and is not zero
4. Source account can transfer money, and destination account can receive money (their roles have these permissions)
5. Description length is less than 100*1024 (one hundred kilobytes) and less than 'MaxDescriptionSize' setting value if set.

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not transfer asset", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to transfer asset from his account", "Grant the necessary permission"
    "3", "No such source account", "Cannot find account with such id to transfer money from", "Make sure source account id is correct"
    "4", "No such destination account", "Cannot find account with such id to transfer money to", "Make sure destination account id is correct"
    "5", "No such asset found", "Cannot find such asset", "Make sure asset name and precision are correct"
    "6", "Not enough balance", "Source account's balance is too low to perform the operation", "Add asset to account or choose lower value to subtract"
    "7", "Too much asset to transfer", "Resulting asset quantity of destination account would exceed the allowed maximum", "Make sure that the final destination value is less than 2^256 / 10^asset_precision"
    "8", "Too long description", "Too long description", "Ensure that description length matches the criteria above (or just shorten it)"

.. [#f1] https://www.ietf.org/rfc/rfc1035.txt
.. [#f2] https://www.ietf.org/rfc/rfc1123.txt

Compare and Set Account Detail
------------------------------

Purpose
^^^^^^^

Purpose of compare and set account detail command is to set key-value information for a given account if the old value matches the value passed.

Schema
^^^^^^

.. code-block:: proto

    message CompareAndSetAccountDetail{
        string account_id = 1;
        string key = 2;
        string value = 3;
        oneof opt_old_value {
            string old_value = 4;
        }
        bool check_empty = 5;
    }

.. note::
    Pay attention, that old_value field is optional.
    This is due to the fact that the key-value pair might not exist.

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Account ID", "id of the account to which the key-value information was set. If key-value pair doesnot exist , then it will be created", "an existing account", "artyom@soramitsu"
    "Key", "key of information being set", "`[A-Za-z0-9_]{1,64}`", "Name"
    "Value", "new value for the corresponding key", "length of value ≤ 4096", "Artyom"
    "Old value", "current value for the corresponding key", "length of value ≤ 4096", "Artem"
    "check_empty", "if true, empty old_value in command must match absent value in WSV; if false, any old_value in command matches absent in WSV (legacy)", "bool", "true"

Validation
^^^^^^^^^^

Three cases:

    Case 1. When transaction creator wants to set account detail to his/her account and he or she has permission GetMyAccountDetail / GetAllAccountsDetail / GetDomainAccountDetail

    Case 2. When transaction creator wants to set account detail to another account and he or she has permissions SetAccountDetail and GetAllAccountsDetail / GetDomainAccountDetail

    Case 3. SetAccountDetail permission was granted to transaction creator and he or she has permission GetAllAccountsDetail / GetDomainAccountDetail

Possible Stateful Validation Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Code", "Error Name", "Description", "How to solve"

    "1", "Could not compare and set account detail", "Internal error happened", "Try again or contact developers"
    "2", "No such permissions", "Command's creator does not have permission to set and read account detail for this account", "Grant the necessary permission"
    "3", "No such account", "Cannot find account to set account detail to", "Make sure account id is correct"
    "4", "No match values", "Old values do not match", "Make sure old value is correct"

Set setting value
-----------------

Purpose
^^^^^^^

The purpose of set setting value command is to enable customization to your needs.


Schema
^^^^^^

.. code-block:: proto

    message SetSettingValue {
        string key = 1;
        string value = 2;
    }

Structure
^^^^^^^^^

.. csv-table::
    :header: "Field", "Description", "Constraint", "Example"
    :widths: 15, 30, 20, 15

    "Key", "Key of the setting", "list of possible settings", "MaxDescriptionSize"
    "Value", "Value of the setting", "type of setting", "255"


Validation
^^^^^^^^^^

1. Command can be executed only from genesis block

List of possible settings
^^^^^^^^^^^^^^^^^^^^^^^^^

.. csv-table::
    :header: "Key", "Value constraint", "Description"

    "MaxDescriptionSize", "Unsigned integer, 0 <= MaxDescriptionSize < 2^32", "Maximum transaction description length"
