#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

from iroha import Iroha, IrohaCrypto
from iroha import primitive_pb2
import commons

admin = commons.new_user('admin@first')
alice = commons.new_user('alice@second')
iroha = Iroha(admin['id'])


@commons.hex
def genesis_tx():
    test_permissions = [
        primitive_pb2.can_get_all_acc_ast_txs,
        primitive_pb2.can_receive,
        primitive_pb2.can_transfer
    ]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions, multidomain=True)
    genesis_commands.extend([
        iroha.command('CreateAsset', asset_name='coin', domain_id='first', precision=2),
        iroha.command('AddAssetQuantity', asset_id='coin#first', amount='300.00'),
        iroha.command('TransferAsset',
                      src_account_id=admin['id'],
                      dest_account_id=alice['id'],
                      asset_id='coin#first',
                      description='top up',
                      amount='200.00')
    ])
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def account_asset_transactions_query():
    query = iroha.query('GetAccountAssetTransactions', creator_account=alice['id'], page_size=10,
                        account_id=admin['id'], asset_id='coin#first')
    IrohaCrypto.sign_query(query, alice['key'])
    return query
