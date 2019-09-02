Javascript library
------------------

.. image:: https://img.shields.io/npm/v/iroha-helpers.svg

This library provides functions which will help you to interact with Hyperledger Iroha from your JS program.

Installation
^^^^^^^^^^^^
Via npm

.. code:: sh

    $ npm i iroha-helpers

Via yarn

.. code:: sh

    $ yarn add iroha-helpers

Commands
^^^^^^^^
For usage of any command you need to provide ``commandOptions`` as a first argument.

.. code-block:: javascript

  const commandOptions = {
    privateKeys: ['f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70'], // Array of private keys in hex format
    creatorAccountId: '', // Account id, ex. admin@test
    quorum: 1,
    commandService: null
  }

As second argument you need to provide object that contains properties for required command.

.. code-block:: javascript
  
  // Example usage of setAccountDetail

  const commandService = new CommandService_v1Client(
    '127.0.0.1:50051',
    grpc.credentials.createInsecure()
  )

  const adminPriv = 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70'

  commands.setAccountDetail({
    privateKeys: [adminPriv],
    creatorAccountId: 'admin@test',
    quorum: 1,
    commandService
  }, {
    accountId: 'admin@test',
    key: 'jason',
    value: 'statham'
  })

Queries
^^^^^^^
For usage of any query you need to provide ``queryOptions`` as a first argument.

.. code-block:: javascript

  const queryOptions = {
    privateKey: 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70', // Private key in hex format
    creatorAccountId: '', // Account id, ex. admin@test
    queryService: null
  }

As second argument you need to provide object that contains properties for required query.

.. code-block:: javascript
  
  // Example usage of getAccountDetail
  
  const queryService = new QueryService_v1Client(
    '127.0.0.1:50051',
    grpc.credentials.createInsecure()
  )

  const adminPriv = 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70'

  queries.getAccountDetail({
    privateKey: adminPriv,
    creatorAccountId: 'admin@test',
    queryService
  }, {
    accountId: 'admin@test'
  })

Example code
^^^^^^^^^^^^

.. code-block:: javascript

  import grpc from 'grpc'
  import {
    QueryService_v1Client,
    CommandService_v1Client
  } from '../iroha-helpers/lib/proto/endpoint_grpc_pb'
  import { commands, queries } from 'iroha-helpers'

  const IROHA_ADDRESS = 'localhost:50051'
  const adminPriv =
    'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70'

  const commandService = new CommandService_v1Client(
    IROHA_ADDRESS,
    grpc.credentials.createInsecure()
  )

  const queryService = new QueryService_v1Client(
    IROHA_ADDRESS,
    grpc.credentials.createInsecure()
  )

  Promise.all([
    commands.setAccountDetail({
      privateKeys: [adminPriv],
      creatorAccountId: 'admin@test',
      quorum: 1,
      commandService
    }, {
      accountId: 'admin@test',
      key: 'jason',
      value: 'statham'
    }),
    queries.getAccountDetail({
      privateKey: adminPriv,
      creatorAccountId: 'admin@test',
      queryService
    }, {
      accountId: 'admin@test'
    })
  ])
    .then(a => console.log(a))
    .catch(e => console.error(e))