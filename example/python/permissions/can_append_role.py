#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

from iroha import Iroha, IrohaCrypto
from iroha import primitive_pb2
import commons

admin = commons.new_user('admin@test')
alice = commons.new_user('alice@test')
bob = commons.new_user('bob@test')
iroha = Iroha(admin['id'])


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_append_role, primitive_pb2.can_add_peer]
    second_role_permissions = [primitive_pb2.can_add_peer]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.extend([
        iroha.command('CreateRole', role_name='second_role', permissions=second_role_permissions),
        iroha.command('CreateAccount', account_name='bob', domain_id='test',
                      public_key=IrohaCrypto.derive_public_key(bob['key'])),
        iroha.command('AppendRole', account_id=alice['id'], role_name='second_role')
    ])
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def append_role_tx():
    # Note that you can append only that role that has
    # lesser or the same set of permissions as transaction creator.
    tx = iroha.transaction([
        iroha.command('AppendRole', account_id=bob['id'], role_name='second_role')
    ], creator_account=alice['id'])
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
