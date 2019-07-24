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

peer_key = irohalib.IrohaCrypto.private_key()
peer = primitive_pb2.Peer()
peer.address = '192.168.10.10:50541'
peer.peer_key = irohalib.IrohaCrypto.derive_public_key(peer_key)


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_remove_peer]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(irohalib.Iroha.command('AddPeer', peer=peer))
    tx = iroha.transaction(genesis_commands)
    irohalib.IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def remove_peer_tx():
    peer_key = irohalib.IrohaCrypto.private_key()
    tx = iroha.transaction([
        iroha.command('RemovePeer', public_key=peer.peer_key)
    ], creator_account=alice['id'])
    irohalib.IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
