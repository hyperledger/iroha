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
    test_permissions = [primitive_pb2.can_set_quorum]
    extra_key = irohalib.IrohaCrypto.private_key()
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(
        iroha.command('AddSignatory', account_id=alice['id'],
                      public_key=irohalib.IrohaCrypto.derive_public_key(extra_key))
    )
    tx = iroha.transaction(genesis_commands)
    irohalib.IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def set_quorum_tx():
    # Quourum cannot be greater than amount of keys linked to an account
    tx = iroha.transaction([
        iroha.command('SetAccountQuorum', account_id=alice['id'], quorum=2)
    ], creator_account=alice['id'])
    irohalib.IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
