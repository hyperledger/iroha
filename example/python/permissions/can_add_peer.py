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
    test_permissions = [primitive_pb2.can_add_peer]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    tx = iroha.transaction(genesis_commands)
    irohalib.IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def add_peer_tx():
    peer_key = irohalib.IrohaCrypto.private_key()
    peer = primitive_pb2.Peer()
    peer.address = '192.168.10.10:50541'
    peer.peer_key = irohalib.IrohaCrypto.derive_public_key(peer_key)
    tx = iroha.transaction([
        iroha.command('AddPeer', peer=peer)
    ], creator_account=alice['id'])
    irohalib.IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
