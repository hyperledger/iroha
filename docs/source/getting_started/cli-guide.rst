CLI guide: sending your first transactions and queries
======================================================

You can interact with Iroha using various ways.
You can use our client libraries
to write code in various programming languages (e.g. Java, Python, Javascript,
Swift) which communicates with Iroha.
Alternatively, you can use ``iroha-cli`` – our command-line tool for interacting with Iroha.
As a part of this guide, let's get familiar with ``iroha-cli``

.. Attention:: Despite that ``iroha-cli`` is arguably the simplest way to start working with Iroha,
  ``iroha-cli`` covers only some possible commands/queries, so user experience might not be the best.
  If you want to help us build a better CLI version please let us know!

.. raw:: html

  <script src="https://asciinema.org/a/6dFA3CWHQOgaYbKfQXtzApDob.js" id="asciicast-6dFA3CWHQOgaYbKfQXtzApDob" async></script>

Open a new terminal (note that Iroha container and ``irohad`` should be up and
running) and attach to an ``iroha`` docker container:

.. code-block:: shell

  docker exec -it iroha /bin/bash

Now you are in the interactive shell of Iroha's container again.
We need to launch ``iroha-cli`` and pass an account name of the desired user.
In our example, the account ``admin`` is already created in the ``test`` domain.
Let's use this account to work with Iroha.

.. code-block:: shell

  iroha-cli -account_name admin@test

.. note:: Full account name has a ``@`` symbol between name and domain.
  Note that the keypair has the same name.

Creating the First Transaction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can see the interface of ``iroha-cli`` now.
Let's create a new asset, add some asset to the admin account and transfer it to other account.
To achieve this, please choose option ``1. New transaction (tx)`` by writing ``tx`` or ``1`` to a console.

Now you can see a list of available commands.
Let's try creating a new asset.
Select ``14. Create Asset (crt_ast)``.
Now enter a name for your asset, for example ``coolcoin``.
Next, enter a Domain ID. In our example we already have a domain ``test``, so let's use it.
Then we need to enter an asset precision
– the amount of numbers in a fractional part.
Let's set precision to ``2``.

Congratulations, you have created your first command and added it to a transaction!
You can either send it to Iroha or add some more commands
``1. Add one more command to the transaction (add)``.
Let's add more commands, so we can do everything in one shot. Type ``add``.

Now try adding some ``coolcoins`` to our account.
Select ``16. Add Asset Quantity (add_ast_qty)``, enter asset ID – ``coolcoin#test``,
integer part and ``coolcoin#test``, integer part and precision.
For example, to add 200.50 precision.
For example, to add 200.50 ``coolcoins``, we need to enter integer ``coolcoins``,
we need to enter integer part as ``20050`` and precision as  part as ``20050``
and precision as ``2``, so it becomes ``200.50``.

.. note:: Full asset name has a ``#`` symbol between name and domain.

Let's transfer 100.50 ``coolcoins`` from ``admin@test`` to ``test@test``
by adding one more command and choosing ``5. Transfer Assets (tran_ast)``.
Enter Source Account and Destination Account, in our case ``admin@test``
and ``test@test``, Asset ID (``coolcoin#test``), integer part and precision (``10050`` and ``2`` accordingly).

Now we need to send our transaction to Iroha peer (``2. Send to Iroha peer (send)``).
Enter peer address (in our case ``localhost``) and port (``50051``).
Now your transaction is submitted and you can see your transaction hash.
You can use it to check transaction's status.

Go back to a terminal where ``irohad`` is running.
You can see logs of your transaction.

Yay! You have submitted your first transaction to Iroha.

Creating the First Query
^^^^^^^^^^^^^^^^^^^^^^^^

Now let's check if ``coolcoins`` were successfully transferred from ``admin@test`` to ``test@test``.
Choose ``2. New query (qry)``.
``8. Get Account's Assets (get_acc_ast)`` can help you to check if ``test@test`` now has ``coolcoin``.
Form a query in a similar way you did with commands you did with commands and ``1. Send to Iroha peer (send)``.
Now you can see information about how many ``coolcoin`` does ``test@test`` have.
It will look similar to this:

.. code-block:: shell

  [2018-03-21 12:33:23.179275525][th:36][info] QueryResponseHandler [Account Assets]
  [2018-03-21 12:33:23.179329199][th:36][info] QueryResponseHandler -Account Id:- test@test
  [2018-03-21 12:33:23.179338394][th:36][info] QueryResponseHandler -Asset Id- coolcoin#test
  [2018-03-21 12:33:23.179387969][th:36][info] QueryResponseHandler -Balance- 100.50

Isn't that awesome?
You have submitted your first query to Iroha and got a response!

.. hint:: To get information about all available commands and queries please check our API section.

Being Badass
^^^^^^^^^^^^

Let's try being badass and cheat Iroha. For example, let's transfer more ``coolcoins`` than ``admin@test`` has.
Try to transfer 100000.00 ``coolcoins`` from ``admin@test`` to ``test@test``.
Again, proceed to ``1. New transaction (tx)``, ``5. Transfer Assets (tran_ast)``,
enter Source Account and Destination Account, in our case ``admin@test`` and ``test@test``, Asset ID (``coolcoin#test``),
integer part and precision (``10000000`` and ``2`` accordingly).
Send a transaction to Iroha peer as you did before.
Well, it says

.. code::

  [2018-03-21 12:58:40.791297963][th:520][info] TransactionResponseHandler Transaction successfully sent
  Congratulation, your transaction was accepted for processing.
  Its hash is fc1c23f2de1b6fccbfe1166805e31697118b57d7bb5b1f583f2d96e78f60c241

`Your transaction was accepted for processing`.
Does it mean that we had successfully cheated Iroha?
Let's try to see transaction's status.
Choose ``3. New transaction status request (st)`` and enter transaction's hash which you can get in the console after the previous command.
Let's send it to Iroha.
It replies with:

.. code::

  Transaction has not passed stateful validation.

Apparently no.
Our transaction was not accepted because it did not pass stateful validation and ``coolcoins`` were not transferred.
You can check the status of ``admin@test`` and ``test@test`` with queries to be sure (like we did earlier).
