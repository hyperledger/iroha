#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import irohalib
import commons
import primitive_pb2

admin = commons.new_user('admin@test')
alice = commons.new_user('alice@test')
bob = commons.new_user('bob@test')
iroha = irohalib.Iroha(admin['id'])


@commons.hex
def genesis_tx():
    test_permissions = [
        primitive_pb2.can_grant_can_remove_my_signatory,
        primitive_pb2.can_add_signatory
    ]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(
        iroha.command('CreateAccount', account_name='bob', domain_id='test',
                      public_key=irohalib.IrohaCrypto.derive_public_key(bob['key']))
    )
    tx = iroha.transaction(genesis_commands)
    irohalib.IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def grant_can_remove_my_signatory_tx():
    extra_key = irohalib.IrohaCrypto.private_key()
    tx = iroha.transaction([
        iroha.command('GrantPermission', account_id=bob['id'], permission=primitive_pb2.can_remove_my_signatory),
        iroha.command('AddSignatory', account_id=alice['id'],
                      public_key=irohalib.IrohaCrypto.derive_public_key(extra_key))
    ], creator_account=alice['id'])
    irohalib.IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx


@commons.hex
def remove_signatory_tx():
    tx = iroha.transaction([
        iroha.command('RemoveSignatory', account_id=alice['id'],
                      public_key=irohalib.IrohaCrypto.derive_public_key(alice['key']))
    ], creator_account=bob['id'])
    irohalib.IrohaCrypto.sign_transaction(tx, bob['key'])
    return tx
