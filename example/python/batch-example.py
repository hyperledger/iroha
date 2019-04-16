#!/usr/bin/env python3
#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import binascii
from irohalib import IrohaCrypto as ic
from irohalib import Iroha, IrohaGrpc
import sys

print("""

PLEASE ENSURE THAT MST IS ENABLED IN IROHA CONFIG

""")


if sys.version_info[0] < 3:
    raise Exception('Python 3 or a more recent version is required.')


iroha = Iroha('admin@test')
net = IrohaGrpc()

admin_private_key = open('../admin@test.priv').read()

alice_private_keys = [
    b'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506caba1',
    b'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506caba2'
]
alice_public_keys = [ic.derive_public_key(x) for x in alice_private_keys]

bob_private_keys = [
    b'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506caba3',
    b'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506caba4'
]
bob_public_keys = [ic.derive_public_key(x) for x in bob_private_keys]


def trace(func):
    """
    A decorator for tracing methods' begin/end execution points
    """
    def tracer(*args, **kwargs):
        name = func.__name__
        print('\tEntering "{}"'.format(name))
        result = func(*args, **kwargs)
        print('\tLeaving "{}"'.format(name))
        return result
    return tracer


@trace
def send_transaction_and_print_status(transaction):
    global net
    hex_hash = binascii.hexlify(ic.hash(transaction))
    print('Transaction hash = {}, creator = {}'.format(
        hex_hash, transaction.payload.reduced_payload.creator_account_id))
    net.send_tx(transaction)
    for status in net.tx_status_stream(transaction):
        print(status)


@trace
def send_batch_and_print_status(*transactions):
    global net
    net.send_txs(*transactions)
    for tx in transactions:
        hex_hash = binascii.hexlify(ic.hash(tx))
        print('\t' + '-' * 20)
        print('Transaction hash = {}, creator = {}'.format(
            hex_hash, tx.payload.reduced_payload.creator_account_id))
        for status in net.tx_status_stream(tx):
            print(status)


@trace
def create_users():
    global iroha
    init_cmds = [
        iroha.command('CreateAsset', asset_name='bitcoin',
                      domain_id='test', precision=2),
        iroha.command('CreateAsset', asset_name='dogecoin',
                      domain_id='test', precision=2),
        iroha.command('AddAssetQuantity',
                      asset_id='bitcoin#test', amount='100000'),
        iroha.command('AddAssetQuantity',
                      asset_id='dogecoin#test', amount='20000'),
        iroha.command('CreateAccount', account_name='alice', domain_id='test',
                      public_key=alice_public_keys[0]),
        iroha.command('CreateAccount', account_name='bob', domain_id='test',
                      public_key=bob_public_keys[0]),
        iroha.command('TransferAsset', src_account_id='admin@test', dest_account_id='alice@test',
                      asset_id='bitcoin#test', description='init top up', amount='100000'),
        iroha.command('TransferAsset', src_account_id='admin@test', dest_account_id='bob@test',
                      asset_id='dogecoin#test', description='init doge', amount='20000')
    ]
    init_tx = iroha.transaction(init_cmds)
    ic.sign_transaction(init_tx, admin_private_key)
    send_transaction_and_print_status(init_tx)


@trace
def add_keys_and_set_quorum():
    alice_iroha = Iroha('alice@test')
    alice_cmds = [
        alice_iroha.command('AddSignatory', account_id='alice@test',
                            public_key=alice_public_keys[1]),
        alice_iroha.command('SetAccountQuorum',
                            account_id='alice@test', quorum=2)
    ]
    alice_tx = alice_iroha.transaction(alice_cmds)
    ic.sign_transaction(alice_tx, alice_private_keys[0])
    send_transaction_and_print_status(alice_tx)

    bob_iroha = Iroha('bob@test')
    bob_cmds = [
        bob_iroha.command('AddSignatory', account_id='bob@test',
                          public_key=bob_public_keys[1]),
        bob_iroha.command('SetAccountQuorum', account_id='bob@test', quorum=2)
    ]
    bob_tx = bob_iroha.transaction(bob_cmds)
    ic.sign_transaction(bob_tx, bob_private_keys[0])
    send_transaction_and_print_status(bob_tx)


@trace
def alice_creates_exchange_batch():
    alice_tx = iroha.transaction(
        [iroha.command(
            'TransferAsset', src_account_id='alice@test', dest_account_id='bob@test', asset_id='bitcoin#test',
            amount='1'
        )],
        creator_account='alice@test',
        quorum=2
    )
    bob_tx = iroha.transaction(
        [iroha.command(
            'TransferAsset', src_account_id='bob@test', dest_account_id='alice@test', asset_id='dogecoin#test',
            amount='2'
        )],
        creator_account='bob@test'
        # we intentionally omit here bob's quorum, since alice is the originator of the exchange and in general case
        # alice does not know bob's quorum.
        # bob knowing own quorum in case of accept should sign the tx using all the number of missing keys at once
    )
    iroha.batch(alice_tx, bob_tx, atomic=True)
    # sign transactions only after batch meta creation
    ic.sign_transaction(alice_tx, *alice_private_keys)
    send_batch_and_print_status(alice_tx, bob_tx)


@trace
def bob_accepts_exchange_request():
    global net
    q = ic.sign_query(
        Iroha('bob@test').query('GetPendingTransactions'),
        bob_private_keys[0]
    )
    pending_transactions = net.send_query(q)
    for tx in pending_transactions.transactions_response.transactions:
        if tx.payload.reduced_payload.creator_account_id == 'alice@test':
            # we need do this temporarily, otherwise accept will not reach MST engine
            del tx.signatures[:]
        else:
            ic.sign_transaction(tx, *bob_private_keys)
    send_batch_and_print_status(
        *pending_transactions.transactions_response.transactions)


@trace
def check_no_pending_txs():
    print(' ~~~ No pending txs expected:')
    print(
        net.send_query(
            ic.sign_query(
                iroha.query('GetPendingTransactions',
                            creator_account='bob@test'),
                bob_private_keys[0]
            )
        )
    )
    print(' ~~~')


@trace
def bob_declines_exchange_request():
    print("""
    
    IT IS EXPECTED HERE THAT THE BATCH WILL FAIL STATEFUL VALIDATION
    
    """)
    global net
    q = ic.sign_query(
        Iroha('bob@test').query('GetPendingTransactions'),
        bob_private_keys[0]
    )
    pending_transactions = net.send_query(q)
    for tx in pending_transactions.transactions_response.transactions:
        if tx.payload.reduced_payload.creator_account_id == 'alice@test':
            # we need do this temporarily, otherwise accept will not reach MST engine
            del tx.signatures[:]
        else:
            # intentionally alice keys were used to fail bob's txs
            ic.sign_transaction(tx, *alice_private_keys)
            # zeroes as private keys are also acceptable
    send_batch_and_print_status(
        *pending_transactions.transactions_response.transactions)


create_users()
add_keys_and_set_quorum()

alice_creates_exchange_batch()
bob_accepts_exchange_request()
check_no_pending_txs()

alice_creates_exchange_batch()
bob_declines_exchange_request()
check_no_pending_txs()
