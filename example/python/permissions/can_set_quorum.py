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
    test_permissions = [primitive_pb2.can_set_quorum]
    extra_key = IrohaCrypto.private_key()
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(
        iroha.command('AddSignatory', account_id=alice['id'],
                      public_key=IrohaCrypto.derive_public_key(extra_key))
    )
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def set_quorum_tx():
    # Quourum cannot be greater than amount of keys linked to an account
    tx = iroha.transaction([
        iroha.command('SetAccountQuorum', account_id=alice['id'], quorum=2)
    ], creator_account=alice['id'])
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
