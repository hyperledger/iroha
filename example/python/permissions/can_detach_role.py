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
    test_permissions = [primitive_pb2.can_detach_role]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def detach_role_tx():
    tx = iroha.transaction([
        iroha.command('DetachRole', account_id=admin['id'], role_name='test_role')
    ], creator_account=alice['id'])
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
