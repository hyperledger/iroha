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

peer_key = IrohaCrypto.private_key()
peer = primitive_pb2.Peer()
peer.address = '192.168.10.10:50541'
peer.peer_key = IrohaCrypto.derive_public_key(peer_key)


@commons.hex
def genesis_tx():
    test_permissions = [primitive_pb2.can_remove_peer]
    genesis_commands = commons.genesis_block(admin, alice, test_permissions)
    genesis_commands.append(Iroha.command('AddPeer', peer=peer))
    tx = iroha.transaction(genesis_commands)
    IrohaCrypto.sign_transaction(tx, admin['key'])
    return tx


@commons.hex
def remove_peer_tx():
    peer_key = IrohaCrypto.private_key()
    tx = iroha.transaction([
        iroha.command('RemovePeer', public_key=peer.peer_key)
    ], creator_account=alice['id'])
    IrohaCrypto.sign_transaction(tx, alice['key'])
    return tx
