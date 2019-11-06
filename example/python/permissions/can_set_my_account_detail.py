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
    test_permissions = [primitive_pb2.can_grant_can_set_my_account_detail]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(
        iroha.command('CreateAccount', account_name='bob', domain_id='test',
                      public_key=IrohaCrypto.derive_public_key(bob['key']))
    )
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def grant_permission_tx():
    tx = iroha.transaction([
        iroha.command('GrantPermission', account_id=bob['id'], permission=primitive_pb2.can_set_my_account_detail)
    ], creator_account=alice['id'])
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx


@commons.hex
def set_detail_tx():
    tx = iroha.transaction([
        iroha.command('SetAccountDetail', account_id=alice['id'], key='fav_year', value='2019')
    ], creator_account=bob['id'])
    IrohaCrypto.sign_transaction(tx, bob['key'])
    return tx
