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
    test_permissions = [primitive_pb2.can_get_roles]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def get_system_roles_query():
    query = iroha.query('GetRoles', creator_account=alice['id'])
    IrohaCrypto.sign_query(query, alice['key'])
    return query


@commons.hex
def get_role_permissions_query():
    query = iroha.query('GetRolePermissions', creator_account=alice['id'], counter=2, role_id='admin_role')
    IrohaCrypto.sign_query(query, alice['key'])
    return query
