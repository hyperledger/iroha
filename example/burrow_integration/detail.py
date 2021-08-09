from Crypto.Hash import keccak
import os
import binascii
from iroha import IrohaCrypto
from iroha import Iroha, IrohaGrpc
from iroha.ed25519 import H


from iroha.primitive_pb2 import can_set_my_account_detail
import sys

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

IROHA_HOST_ADDR = os.getenv("IROHA_HOST_ADDR", "127.0.0.1")
IROHA_PORT = os.getenv("IROHA_PORT", "50051")
ADMIN_ACCOUNT_ID = os.getenv("ADMIN_ACCOUNT_ID", "admin@test")
ADMIN_PRIVATE_KEY = os.getenv(
    "ADMIN_PRIVATE_KEY",
    "f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70",
)


user_private_key = IrohaCrypto.private_key()
user_public_key = IrohaCrypto.derive_public_key(user_private_key)
iroha = Iroha(ADMIN_ACCOUNT_ID)
net = IrohaGrpc("{}:{}".format(IROHA_HOST_ADDR, IROHA_PORT))


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


def get_first_four_bytes_of_keccak(function):
    """Generates the first 4 bytes of the keccak256 hash of the function signature. """
    k = keccak.new(digest_bits=256)
    k.update(function)
    return k.hexdigest()[:8]


@trace
def get_account_details():
    params = get_first_four_bytes_of_keccak(b"getDetail()")
    no_of_param = 0
    tx = iroha.transaction(
        [iroha.command("CallEngine", caller="admin@test", callee=address, input=params)]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    response = net.send_tx(tx)
    for status in net.tx_status_stream(tx):
        print(status)
    hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
    return hex_hash


@trace
def create_contract():
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506108ff806100746000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806346e69273146100465780635b2a4cff14610076578063d4e804ab14610094575b600080fd5b610060600480360381019061005b919061047d565b6100b2565b60405161006d9190610663565b60405180910390f35b61007e610292565b60405161008b9190610663565b60405180910390f35b61009c6103f1565b6040516100a99190610648565b60405180910390f35b606060008484846040516024016100cb93929190610685565b6040516020818303038152906040527f46e69273000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1683604051610192919061061a565b600060405180830381855af49150503d80600081146101cd576040519150601f19603f3d011682016040523d82523d6000602084013e6101d2565b606091505b509150915081610217576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161020e906106d1565b60405180910390fd5b846040516102259190610631565b60405180910390208660405161023b9190610631565b6040518091039020886040516102519190610631565b60405180910390207f5e1b38cd47cf21b75d5051af29fa321eedd94877db5ac62067a076770eddc9d060405160405180910390a48093505050509392505050565b606060006040516024016040516020818303038152906040527f5b2a4cff000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1683604051610363919061061a565b600060405180830381855af49150503d806000811461039e576040519150601f19603f3d011682016040523d82523d6000602084013e6103a3565b606091505b5091509150816103e8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103df906106d1565b60405180910390fd5b80935050505090565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600061042861042384610716565b6106f1565b90508281526020810184848401111561044057600080fd5b61044b8482856107c7565b509392505050565b600082601f83011261046457600080fd5b8135610474848260208601610415565b91505092915050565b60008060006060848603121561049257600080fd5b600084013567ffffffffffffffff8111156104ac57600080fd5b6104b886828701610453565b935050602084013567ffffffffffffffff8111156104d557600080fd5b6104e186828701610453565b925050604084013567ffffffffffffffff8111156104fe57600080fd5b61050a86828701610453565b9150509250925092565b61051d81610795565b82525050565b600061052e82610747565b610538818561075d565b93506105488185602086016107d6565b61055181610869565b840191505092915050565b600061056782610747565b610571818561076e565b93506105818185602086016107d6565b80840191505092915050565b600061059882610752565b6105a28185610779565b93506105b28185602086016107d6565b6105bb81610869565b840191505092915050565b60006105d182610752565b6105db818561078a565b93506105eb8185602086016107d6565b80840191505092915050565b6000610604602783610779565b915061060f8261087a565b604082019050919050565b6000610626828461055c565b915081905092915050565b600061063d82846105c6565b915081905092915050565b600060208201905061065d6000830184610514565b92915050565b6000602082019050818103600083015261067d8184610523565b905092915050565b6000606082019050818103600083015261069f818661058d565b905081810360208301526106b3818561058d565b905081810360408301526106c7818461058d565b9050949350505050565b600060208201905081810360008301526106ea816105f7565b9050919050565b60006106fb61070c565b90506107078282610809565b919050565b6000604051905090565b600067ffffffffffffffff8211156107315761073061083a565b5b61073a82610869565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600081905092915050565b60006107a0826107a7565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b838110156107f45780820151818401526020810190506107d9565b83811115610803576000848401525b50505050565b61081282610869565b810181811067ffffffffffffffff821117156108315761083061083a565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e0000000000000000000000000000000000000000000000000060208201525056fea264697066735822122064304fbb714f30bcd71d8e5903d031552a834fef90217daeedc5c8b78a2efb5664736f6c63430008040033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file detail.sol. """
    tx = iroha.transaction(
        [iroha.command("CallEngine", caller="admin@test", input=bytecode)]
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
def set_account_detail(address):
    params = get_first_four_bytes_of_keccak(b"setDetail(string,string,string)")
    no_of_param = 3
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("admin@test")  # source account id
    params = params + argument_encoding("university")  # domain id
    params = params + argument_encoding("MIT")  #  key
    tx = iroha.transaction(
        [iroha.command("CallEngine", caller="admin@test", callee=address, input=params)]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    response = net.send_tx(tx)
    print(response)
    for status in net.tx_status_stream(tx):
        print(status)
    hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
    return hex_hash


hash = create_contract()
address = get_engine_receipts_address(hash)
hash = get_account_details()
get_engine_receipts_result(hash)
hash = set_account_detail(address)
hash = get_account_details()
get_engine_receipts_result(hash)
print("done")
