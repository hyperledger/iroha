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
    test_permissions = [primitive_pb2.can_grant_can_add_my_signatory]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(
        iroha.command('CreateAccount', account_name='bob', domain_id='test',
                      public_key=IrohaCrypto.derive_public_key(bob['key'])))
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def grant_can_add_my_signatory_tx():
    tx = iroha.transaction([
        iroha.command('GrantPermission', account_id=bob['id'], permission=primitive_pb2.can_add_my_signatory)
    ], creator_account=alice['id'])
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx


@commons.hex
def add_signatory_tx():
    extra_key = IrohaCrypto.private_key()
    tx = iroha.transaction([
        iroha.command('AddSignatory', account_id=alice['id'],
                      public_key=IrohaCrypto.derive_public_key(extra_key))
    ], creator_account=bob['id'])
    IrohaCrypto.sign_transaction(tx, bob['key'])
    return tx
