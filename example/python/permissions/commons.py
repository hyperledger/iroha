#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

from iroha import primitive_pb2
from iroha import Iroha, IrohaCrypto
import binascii
from time import time

command = Iroha.command


def now():
    return int(time() * 1000)


def all_permissions():
    return [
        primitive_pb2.can_append_role,
        primitive_pb2.can_create_role,
        primitive_pb2.can_detach_role,
        primitive_pb2.can_add_asset_qty,
        primitive_pb2.can_subtract_asset_qty,
        primitive_pb2.can_add_peer,
        primitive_pb2.can_add_signatory,
        primitive_pb2.can_remove_signatory,
        primitive_pb2.can_set_quorum,
        primitive_pb2.can_create_account,
        primitive_pb2.can_set_detail,
        primitive_pb2.can_create_asset,
        primitive_pb2.can_transfer,
        primitive_pb2.can_receive,
        primitive_pb2.can_create_domain,
        primitive_pb2.can_read_assets,
        primitive_pb2.can_get_roles,
        primitive_pb2.can_get_my_account,
        primitive_pb2.can_get_all_accounts,
        primitive_pb2.can_get_domain_accounts,
        primitive_pb2.can_get_my_signatories,
        primitive_pb2.can_get_all_signatories,
        primitive_pb2.can_get_domain_signatories,
        primitive_pb2.can_get_my_acc_ast,
        primitive_pb2.can_get_all_acc_ast,
        primitive_pb2.can_get_domain_acc_ast,
        primitive_pb2.can_get_my_acc_detail,
        primitive_pb2.can_get_all_acc_detail,
        primitive_pb2.can_get_domain_acc_detail,
        primitive_pb2.can_get_my_acc_txs,
        primitive_pb2.can_get_all_acc_txs,
        primitive_pb2.can_get_domain_acc_txs,
        primitive_pb2.can_get_my_acc_ast_txs,
        primitive_pb2.can_get_all_acc_ast_txs,
        primitive_pb2.can_get_domain_acc_ast_txs,
        primitive_pb2.can_get_my_txs,
        primitive_pb2.can_get_all_txs,
        primitive_pb2.can_get_blocks,
        primitive_pb2.can_grant_can_set_my_quorum,
        primitive_pb2.can_grant_can_add_my_signatory,
        primitive_pb2.can_grant_can_remove_my_signatory,
        primitive_pb2.can_grant_can_transfer_my_assets,
        primitive_pb2.can_grant_can_set_my_account_detail
    ]


def genesis_block(admin, alice, test_permissions, multidomain=False):
    """
    Compose a set of common for all tests' genesis block transactions
    :param admin: dict of id and private key of admin
    :param alice: dict of id and private key of alice
    :param test_permissions: permissions for users in test domain
    :param multidomain: admin and alice accounts will be created in
    different domains and the first domain users will have admin right
    by default if True
    :return: a list of Iroha.command's
    """
    peer = primitive_pb2.Peer()
    peer.address = '0.0.0.0:50541'
    peer.peer_key = IrohaCrypto.derive_public_key(admin['key'])
    commands = [
        command('AddPeer', peer=peer),
        command('CreateRole', role_name='admin_role', permissions=all_permissions()),
        command('CreateRole', role_name='test_role', permissions=test_permissions)]
    if multidomain:
        commands.append(command('CreateDomain', domain_id='first', default_role='admin_role'))
    commands.extend([
        command('CreateDomain',
                domain_id='second' if multidomain else 'test',
                default_role='test_role'),
        command('CreateAccount',
                account_name='admin',
                domain_id='first' if multidomain else 'test',
                public_key=IrohaCrypto.derive_public_key(admin['key'])),
        command('CreateAccount',
                account_name='alice',
                domain_id='second' if multidomain else 'test',
                public_key=IrohaCrypto.derive_public_key(alice['key']))
    ])
    if not multidomain:
        commands.append(command('AppendRole', account_id=admin['id'], role_name='admin_role'))
    return commands


def new_user(user_id):
    private_key = IrohaCrypto.private_key()
    if user_id.lower().startswith('admin'):
        print('K{}'.format(private_key.decode('utf-8')))
    return {
        'id': user_id,
        'key': private_key
    }


def hex(generator):
    """
    Decorator for transactions' and queries generators.

    Allows preserving the type of binaries for Binary Testing Framework.
    """
    prefix = 'T' if generator.__name__.lower().endswith('tx') else 'Q'
    print('{}{}'.format(prefix, binascii.hexlify(generator().SerializeToString()).decode('utf-8')))
