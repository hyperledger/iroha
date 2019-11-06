#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

from iroha import Iroha, IrohaCrypto
from iroha import primitive_pb2
import commons

admin = commons.new_user('admin@test')
alice = commons.new_user('alice@test')
iroha = Iroha(admin['id'])


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_get_my_acc_ast_txs]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.extend([
        iroha.command('CreateAsset', asset_name='coin', domain_id='test', precision=2),
        iroha.command('AddAssetQuantity', asset_id='coin#test', amount='500.69'),
        iroha.command('TransferAsset',
                      src_account_id=admin['id'],
                      dest_account_id=alice['id'],
                      asset_id='coin#test',
                      description='top up',
                      amount='10.00')
    ])
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def account_asset_transactions_query():
    query = iroha.query('GetAccountAssetTransactions', creator_account=alice['id'], account_id=alice['id'],
                        asset_id='coin#test', page_size=10)
    IrohaCrypto.sign_query(query, alice['key'])
    return query
