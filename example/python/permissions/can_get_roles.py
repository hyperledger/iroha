#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import irohalib
import commons
import primitive_pb2

admin = commons.new_user('admin@test')
alice = commons.new_user('alice@test')
iroha = irohalib.Iroha(admin['id'])


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_get_roles]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    tx = iroha.transaction(genesis_commands)
    irohalib.IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def get_system_roles_query():
    query = iroha.query('GetRoles', creator_account=alice['id'])
    irohalib.IrohaCrypto.sign_query(query, alice['key'])
    return query


@commons.hex
def get_role_permissions_query():
    query = iroha.query('GetRolePermissions', creator_account=alice['id'], counter=2, role_id='admin_role')
    irohalib.IrohaCrypto.sign_query(query, alice['key'])
    return query
