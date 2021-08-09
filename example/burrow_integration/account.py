import os
import binascii
from iroha import IrohaCrypto
from iroha import Iroha, IrohaGrpc
from iroha.primitive_pb2 import can_set_my_account_detail
import sys
from Crypto.Hash import keccak

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

# Here is the information about the environment and admin account information:
IROHA_HOST_ADDR = os.getenv("IROHA_HOST_ADDR", "127.0.0.1")
IROHA_PORT = os.getenv("IROHA_PORT", "50051")
ADMIN_ACCOUNT_ID = os.getenv("ADMIN_ACCOUNT_ID", "admin@test")
ADMIN_PRIVATE_KEY = os.getenv(
    "ADMIN_PRIVATE_KEY",
    "f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70",
)

iroha = Iroha(ADMIN_ACCOUNT_ID)
net = IrohaGrpc("{}:{}".format(IROHA_HOST_ADDR, IROHA_PORT))

test_private_key = IrohaCrypto.private_key()
test_public_key = IrohaCrypto.derive_public_key(test_private_key).decode("utf-8")


def trace(func):
    """
    A decorator for tracing methods' begin/end execution points
    """

    def tracer(*args, **kwargs):
        name = func.__name__
        print('\tEntering "{}"'.format(name))
        result = func(*args, **kwargs)
        print('\tLeaving "{}"'.format(name))
        return result

    return tracer


def make_number_hex_left_padded(number: str, width: int = 64):
    number_hex = "{:x}".format(number)
    return str(number_hex).zfill(width)


def left_padded_address_of_param(
    param_index: int, number_of_params: int, width: int = 64
):
    """Specifies the position of each argument according to Contract AbI specifications."""
    bits_offset = 32 * number_of_params
    bits_per_param = 64
    bits_for_the_param = bits_offset + bits_per_param * param_index
    return make_number_hex_left_padded(bits_for_the_param, width)


def argument_encoding(arg):
    """Encodes the argument according to Contract ABI specifications."""
    encoded_argument = str(hex(len(arg)))[2:].zfill(64)
    encoded_argument = (
        encoded_argument + arg.encode("utf8").hex().ljust(64, "0").upper()
    )
    return encoded_argument


def get_first_four_bytes_of_keccak(function_signature: str):
    """Generates the first 4 bytes of the keccak256 hash of the function signature. """
    k = keccak.new(digest_bits=256)
    k.update(function_signature)
    return k.hexdigest()[:8]


@trace
def create_contract():
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555061096b806100746000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80634518f6b314610046578063bc53c0c414610076578063d4e804ab146100a6575b600080fd5b610060600480360381019061005b9190610486565b6100c4565b60405161006d91906106ad565b60405180910390f35b610090600480360381019061008b91906104c7565b610230565b60405161009d91906106ad565b60405180910390f35b6100ae6103fa565b6040516100bb9190610692565b60405180910390f35b60606000826040516024016100d991906106cf565b6040516020818303038152906040527f4518f6b3000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516101a09190610664565b600060405180830381855af49150503d80600081146101db576040519150601f19603f3d011682016040523d82523d6000602084013e6101e0565b606091505b509150915081610225576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161021c9061073d565b60405180910390fd5b809350505050919050565b60606000848484604051602401610249939291906106f1565b6040516020818303038152906040527fbc53c0c4000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516103109190610664565b600060405180830381855af49150503d806000811461034b576040519150601f19603f3d011682016040523d82523d6000602084013e610350565b606091505b509150915081610395576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161038c9061073d565b60405180910390fd5b856040516103a3919061067b565b6040518091039020876040516103b9919061067b565b60405180910390207fb4086b7a9e5eac405225b6c630a4147f0a8dcb4af3583733b10db7b91ad21ffd60405160405180910390a38093505050509392505050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600061043161042c84610782565b61075d565b90508281526020810184848401111561044957600080fd5b610454848285610833565b509392505050565b600082601f83011261046d57600080fd5b813561047d84826020860161041e565b91505092915050565b60006020828403121561049857600080fd5b600082013567ffffffffffffffff8111156104b257600080fd5b6104be8482850161045c565b91505092915050565b6000806000606084860312156104dc57600080fd5b600084013567ffffffffffffffff8111156104f657600080fd5b6105028682870161045c565b935050602084013567ffffffffffffffff81111561051f57600080fd5b61052b8682870161045c565b925050604084013567ffffffffffffffff81111561054857600080fd5b6105548682870161045c565b9150509250925092565b61056781610801565b82525050565b6000610578826107b3565b61058281856107c9565b9350610592818560208601610842565b61059b816108d5565b840191505092915050565b60006105b1826107b3565b6105bb81856107da565b93506105cb818560208601610842565b80840191505092915050565b60006105e2826107be565b6105ec81856107e5565b93506105fc818560208601610842565b610605816108d5565b840191505092915050565b600061061b826107be565b61062581856107f6565b9350610635818560208601610842565b80840191505092915050565b600061064e6027836107e5565b9150610659826108e6565b604082019050919050565b600061067082846105a6565b915081905092915050565b60006106878284610610565b915081905092915050565b60006020820190506106a7600083018461055e565b92915050565b600060208201905081810360008301526106c7818461056d565b905092915050565b600060208201905081810360008301526106e981846105d7565b905092915050565b6000606082019050818103600083015261070b81866105d7565b9050818103602083015261071f81856105d7565b9050818103604083015261073381846105d7565b9050949350505050565b6000602082019050818103600083015261075681610641565b9050919050565b6000610767610778565b90506107738282610875565b919050565b6000604051905090565b600067ffffffffffffffff82111561079d5761079c6108a6565b5b6107a6826108d5565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600081905092915050565b600061080c82610813565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b83811015610860578082015181840152602081019050610845565b8381111561086f576000848401525b50505050565b61087e826108d5565b810181811067ffffffffffffffff8211171561089d5761089c6108a6565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e0000000000000000000000000000000000000000000000000060208201525056fea2646970667358221220d4817d49a28d15d9f85d3db920c232df2a28301e5b8da18bb8f7fa8899cbb4b464736f6c63430008040033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file account.sol. """
    tx = iroha.transaction(
        [iroha.command("CallEngine", caller=ADMIN_ACCOUNT_ID, input=bytecode)]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    net.send_tx(tx)
    hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
    for status in net.tx_status_stream(tx):
        print(status)
    return hex_hash


@trace
def get_engine_receipts_address(tx_hash: str):
    query = iroha.query("GetEngineReceipts", tx_hash=tx_hash)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
    response = net.send_query(query)
    contract_add = response.engine_receipts_response.engine_receipts[0].contract_address
    return contract_add


@trace
def get_engine_receipts_result(tx_hash: str):
    query = iroha.query("GetEngineReceipts", tx_hash=tx_hash)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
    response = net.send_query(query)
    result = response.engine_receipts_response.engine_receipts[
        0
    ].call_result.result_data
    bytes_object = bytes.fromhex(result)
    ascii_string = bytes_object.decode("ASCII", "ignore")
    print(ascii_string)


@trace
def add_asset(address):
    params = get_first_four_bytes_of_keccak(b"addAsset(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("coin#domain")  # asset id
    params = params + argument_encoding("500")  # amount of asset
    tx = iroha.transaction(
        [
            iroha.command(
                "CallEngine", caller=ADMIN_ACCOUNT_ID, callee=address, input=params
            )
        ]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    response = net.send_tx(tx)
    for status in net.tx_status_stream(tx):
        print(status)


@trace
def create_account(address):
    params = get_first_four_bytes_of_keccak(b"createAccount(string,string,string)")
    no_of_param = 3
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("test")  # source account id
    params = params + argument_encoding("burrow")  # domain id
    params = params + argument_encoding(test_public_key)  #  key
    tx = iroha.transaction(
        [
            iroha.command(
                "CallEngine", caller=ADMIN_ACCOUNT_ID, callee=address, input=params
            )
        ]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    response = net.send_tx(tx)
    for status in net.tx_status_stream(tx):
        print(status)
    hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
    return hex_hash


@trace
def get_account(address):
    params = get_first_four_bytes_of_keccak(b"getAccount(string)")
    no_of_param = 1
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("test@burrow")  # account id
    tx = iroha.transaction(
        [
            iroha.command(
                "CallEngine", caller=ADMIN_ACCOUNT_ID, callee=address, input=params
            )
        ]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    response = net.send_tx(tx)
    for status in net.tx_status_stream(tx):
        print(status)
    hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
    return hex_hash


hash = create_contract()
address = get_engine_receipts_address(hash)
create_account(address)
hash = get_account(address)
get_engine_receipts_result(hash)
print("done")
