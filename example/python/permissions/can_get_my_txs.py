#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

from iroha import Iroha, IrohaCrypto
from iroha import primitive_pb2
import commons
import binascii

admin = commons.new_user('admin@first')
alice = commons.new_user('alice@second')
iroha = Iroha(admin['id'])

alice_tx1_hash = None
alice_tx2_hash = None


@commons.hex
def genesis_tx():
    test_permissions = [
        primitive_pb2.can_get_my_txs,
        primitive_pb2.can_add_asset_qty,
        primitive_pb2.can_create_asset
    ]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions, multidomain=True)
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def alice_action_1_tx():
    global alice_tx1_hash
    tx = iroha.transaction([
        iroha.command('CreateAsset', asset_name='coin', domain_id='first', precision=2)
    ], creator_account=alice['id'])
    alice_tx1_hash = IrohaCrypto.hash(tx)
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx


@commons.hex
def alice_action_2_tx():
    global alice_tx2_hash
    tx = iroha.transaction([
        iroha.command('AddAssetQuantity', asset_id='coin#first', amount='600.30')
    ], creator_account=alice['id'])
    alice_tx2_hash = IrohaCrypto.hash(tx)
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx


@commons.hex
def transactions_query():
    hashes = [
        binascii.hexlify(alice_tx1_hash),
        binascii.hexlify(alice_tx2_hash)
    ]
    query = iroha.query('GetTransactions', creator_account=alice['id'], tx_hashes=hashes)
    IrohaCrypto.sign_query(query, alice['key'])
    return query
