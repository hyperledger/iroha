import argparse
import binascii
import iroha
import os
import test_kv

IROHA_HOST_ADDR = os.getenv('IROHA_HOST_ADDR', '127.0.0.1')
IROHA_PORT = os.getenv('IROHA_PORT', '50051')
ADMIN_ACCOUNT_ID = os.getenv('ADMIN_ACCOUNT_ID', 'admin@test')
ADMIN_PRIVATE_KEY = os.getenv(
    'ADMIN_PRIVATE_KEY',
    'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70')

iroha_client = iroha.Iroha(ADMIN_ACCOUNT_ID)
net = iroha.IrohaGrpc('{}:{}'.format(IROHA_HOST_ADDR, IROHA_PORT))


def make_base_kv_command():
    cmd = test_kv.kv_schema_pb2.Command()
    cmd.dm_id.name = 'test_kv'
    cmd.dm_id.version = '0.1.0'
    return cmd


def make_kv_set_command(key, value):
    cmd = make_base_kv_command()
    cmd.payload.set.CopyFrom(test_kv.kv_schema_pb2.Set())
    cmd.payload.set.key = key
    cmd.payload.set.value = value
    return cmd


def make_kv_nuke_command():
    cmd = make_base_kv_command()
    cmd.payload.nuke.CopyFrom(test_kv.kv_schema_pb2.Nuke())
    return cmd


def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(iroha.IrohaCrypto.hash(transaction))
    print('Transaction hash = {}, creator = {}'.format(
        hex_hash, transaction.payload.reduced_payload.creator_account_id))
    net.send_tx(transaction)
    for status in net.tx_status_stream(transaction):
        print(status)


def send_kv_command_and_print_status(kv_command):
    command = iroha.commands_pb2.Command()
    command.call_model.CopyFrom(
        iroha.commands_pb2.CallModel.FromString(
            kv_command.SerializePartialToString()))
    tx = iroha.IrohaCrypto.sign_transaction(
        iroha_client.transaction([command]), ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--set',
        help='send a set command, param: key=val',
    )

    parser.add_argument(
        '--nuke',
        action='store_true',
        help='send a nuke command',
    )

    args = parser.parse_args()
    if args.nuke:
        send_kv_command_and_print_status(make_kv_nuke_command())
    elif args.set:
        send_kv_command_and_print_status(
            make_kv_set_command(*args.set.split('=')))
