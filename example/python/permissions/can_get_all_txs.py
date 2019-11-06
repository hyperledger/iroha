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

admin_tx1_hash = None
admin_tx2_hash = None


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_get_all_txs]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions, multidomain=True)
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def admin_action_1_tx():
    global admin_tx1_hash
    tx = iroha.transaction([
        iroha.command('CreateAsset', asset_name='coin', domain_id='second', precision=2)
    ])
    admin_tx1_hash = IrohaCrypto.hash(tx)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def admin_action_2_tx():
    global admin_tx2_hash
    tx = iroha.transaction([
        iroha.command('SetAccountDetail', account_id=admin['id'], key='hyperledger', value='iroha')
    ])
    admin_tx2_hash = IrohaCrypto.hash(tx)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def transactions_query():
    hashes = [
        binascii.hexlify(admin_tx1_hash),
        binascii.hexlify(admin_tx2_hash)
    ]
    query = iroha.query('GetTransactions', tx_hashes=hashes, creator_account=alice['id'])
    IrohaCrypto.sign_query(query, alice['key'])
    return query
