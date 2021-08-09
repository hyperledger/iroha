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
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555061081d806100746000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063094d1a1614610046578063d4e804ab14610076578063f5496cc514610094575b600080fd5b610060600480360381019061005b919061042e565b6100c4565b60405161006d91906105a1565b60405180910390f35b61007e610233565b60405161008b9190610586565b60405180910390f35b6100ae60048036038101906100a9919061042e565b610257565b6040516100bb91906105a1565b60405180910390f35b6060600083836040516024016100db9291906105c3565b6040516020818303038152906040527f094d1a16000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516101a2919061056f565b600060405180830381855af49150503d80600081146101dd576040519150601f19603f3d011682016040523d82523d6000602084013e6101e2565b606091505b509150915081610227576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161021e906105fa565b60405180910390fd5b80935050505092915050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60606000838360405160240161026e9291906105c3565b6040516020818303038152906040527ff5496cc5000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1683604051610335919061056f565b600060405180830381855af49150503d8060008114610370576040519150601f19603f3d011682016040523d82523d6000602084013e610375565b606091505b5091509150816103ba576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103b1906105fa565b60405180910390fd5b80935050505092915050565b60006103d96103d48461063f565b61061a565b9050828152602081018484840111156103f157600080fd5b6103fc8482856106e5565b509392505050565b600082601f83011261041557600080fd5b81356104258482602086016103c6565b91505092915050565b6000806040838503121561044157600080fd5b600083013567ffffffffffffffff81111561045b57600080fd5b61046785828601610404565b925050602083013567ffffffffffffffff81111561048457600080fd5b61049085828601610404565b9150509250929050565b6104a3816106b3565b82525050565b60006104b482610670565b6104be8185610686565b93506104ce8185602086016106f4565b6104d781610787565b840191505092915050565b60006104ed82610670565b6104f78185610697565b93506105078185602086016106f4565b80840191505092915050565b600061051e8261067b565b61052881856106a2565b93506105388185602086016106f4565b61054181610787565b840191505092915050565b60006105596027836106a2565b915061056482610798565b604082019050919050565b600061057b82846104e2565b915081905092915050565b600060208201905061059b600083018461049a565b92915050565b600060208201905081810360008301526105bb81846104a9565b905092915050565b600060408201905081810360008301526105dd8185610513565b905081810360208301526105f18184610513565b90509392505050565b600060208201905081810360008301526106138161054c565b9050919050565b6000610624610635565b90506106308282610727565b919050565b6000604051905090565b600067ffffffffffffffff82111561065a57610659610758565b5b61066382610787565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b60006106be826106c5565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b838110156107125780820151818401526020810190506106f7565b83811115610721576000848401525b50505050565b61073082610787565b810181811067ffffffffffffffff8211171561074f5761074e610758565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e0000000000000000000000000000000000000000000000000060208201525056fea26469706673582212201e89f14f73d8e6645294211765d8c5ce367bb5484ce54875cbbf943cbdb6c4bf64736f6c63430008040033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file role.sol. """
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
def append_role(address):
    params = get_first_four_bytes_of_keccak(b"appendRole(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("test@burrow")  # account id
    params = params + argument_encoding("money_creator")  # role id
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
def detach_role(address):
    params = get_first_four_bytes_of_keccak(b"detachRole(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("test@burrow")  # account id
    params = params + argument_encoding("money_creator")  # role id
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
append_role(address)
detach_role(address)


print("done")
