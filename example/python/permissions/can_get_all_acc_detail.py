#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import irohalib
import commons
import primitive_pb2

admin = commons.new_user('admin@first')
alice = commons.new_user('alice@second')
iroha = irohalib.Iroha(admin['id'])


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_get_all_acc_detail]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions, multidomain=True)
    tx = iroha.transaction(genesis_commands)
    irohalib.IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def account_detail_query():
    query = iroha.query('GetAccountDetail', creator_account=alice['id'], account_id=admin['id'])
    irohalib.IrohaCrypto.sign_query(query, alice['key'])
    return query
