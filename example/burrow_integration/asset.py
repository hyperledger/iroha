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
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550611260806100746000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063a28abc6e1161005b578063a28abc6e14610112578063cd5286d014610142578063d4e804ab14610172578063de58d156146101905761007d565b80632c74aaaf1461008257806337410dfa146100b257806362d857a0146100e2575b600080fd5b61009c60048036038101906100979190610c87565b6101c0565b6040516100a99190610efc565b60405180910390f35b6100cc60048036038101906100c79190610c87565b61032f565b6040516100d99190610efc565b60405180910390f35b6100fc60048036038101906100f79190610c87565b6104eb565b6040516101099190610efc565b60405180910390f35b61012c60048036038101906101279190610c87565b6106b2565b6040516101399190610efc565b60405180910390f35b61015c60048036038101906101579190610c46565b61086e565b6040516101699190610efc565b60405180910390f35b61017a6109da565b6040516101879190610ee1565b60405180910390f35b6101aa60048036038101906101a59190610cf3565b6109fe565b6040516101b79190610efc565b60405180910390f35b6060600083836040516024016101d7929190610f40565b6040516020818303038152906040527f260b5d52000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161029e9190610eb3565b600060405180830381855af49150503d80600081146102d9576040519150601f19603f3d011682016040523d82523d6000602084013e6102de565b606091505b509150915081610323576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161031a90610fe3565b60405180910390fd5b80935050505092915050565b606060008383604051602401610346929190610f40565b6040516020818303038152906040527f37410dfa000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161040d9190610eb3565b600060405180830381855af49150503d8060008114610448576040519150601f19603f3d011682016040523d82523d6000602084013e61044d565b606091505b509150915081610492576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161048990610fc3565b60405180910390fd5b856040516104a09190610eca565b60405180910390207fd8ea495c3185a632d25d8ccc5c355aeb4058bfaaaee8647c075dc5c1ce62914c866040516104d79190610f1e565b60405180910390a280935050505092915050565b606060008383604051602401610502929190610f40565b6040516020818303038152906040527f62d857a0000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516105c99190610eb3565b600060405180830381855af49150503d8060008114610604576040519150601f19603f3d011682016040523d82523d6000602084013e610609565b606091505b50915091508161064e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161064590610fc3565b60405180910390fd5b8460405161065c9190610eca565b6040518091039020866040516106729190610eca565b60405180910390207f1e5e74355641d99a172207e0d9314c19c416931818c5b0a6551ef3ee5e45494760405160405180910390a380935050505092915050565b6060600083836040516024016106c9929190610f40565b6040516020818303038152906040527fa28abc6e000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516107909190610eb3565b600060405180830381855af49150503d80600081146107cb576040519150601f19603f3d011682016040523d82523d6000602084013e6107d0565b606091505b509150915081610815576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161080c90610fc3565b60405180910390fd5b856040516108239190610eca565b60405180910390207fec7c9835e4ec77a0b862045ec21446c0552c9d2d2847228d8ba172a971683bf48660405161085a9190610f1e565b60405180910390a280935050505092915050565b60606000826040516024016108839190610f1e565b6040516020818303038152906040527fcd5286d0000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161094a9190610eb3565b600060405180830381855af49150503d8060008114610985576040519150601f19603f3d011682016040523d82523d6000602084013e61098a565b606091505b5091509150816109cf576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109c690610fc3565b60405180910390fd5b809350505050919050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60606000848484604051602401610a1793929190610f77565b6040516020818303038152906040527fde58d156000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1683604051610ade9190610eb3565b600060405180830381855af49150503d8060008114610b19576040519150601f19603f3d011682016040523d82523d6000602084013e610b1e565b606091505b509150915081610b63576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b5a90610fc3565b60405180910390fd5b84604051610b719190610eca565b604051809103902086604051610b879190610eca565b604051809103902088604051610b9d9190610eca565b60405180910390207fe5ab145c34a2b2599d0b309bd4b0141f99353ee85ae41cf5afb5761105b177a860405160405180910390a48093505050509392505050565b6000610bf1610bec84611028565b611003565b905082815260208101848484011115610c0957600080fd5b610c148482856110d9565b509392505050565b600082601f830112610c2d57600080fd5b8135610c3d848260208601610bde565b91505092915050565b600060208284031215610c5857600080fd5b600082013567ffffffffffffffff811115610c7257600080fd5b610c7e84828501610c1c565b91505092915050565b60008060408385031215610c9a57600080fd5b600083013567ffffffffffffffff811115610cb457600080fd5b610cc085828601610c1c565b925050602083013567ffffffffffffffff811115610cdd57600080fd5b610ce985828601610c1c565b9150509250929050565b600080600060608486031215610d0857600080fd5b600084013567ffffffffffffffff811115610d2257600080fd5b610d2e86828701610c1c565b935050602084013567ffffffffffffffff811115610d4b57600080fd5b610d5786828701610c1c565b925050604084013567ffffffffffffffff811115610d7457600080fd5b610d8086828701610c1c565b9150509250925092565b610d93816110a7565b82525050565b6000610da482611059565b610dae818561106f565b9350610dbe8185602086016110e8565b610dc78161117b565b840191505092915050565b6000610ddd82611059565b610de78185611080565b9350610df78185602086016110e8565b80840191505092915050565b6000610e0e82611064565b610e18818561108b565b9350610e288185602086016110e8565b610e318161117b565b840191505092915050565b6000610e4782611064565b610e51818561109c565b9350610e618185602086016110e8565b80840191505092915050565b6000610e7a60278361108b565b9150610e858261118c565b604082019050919050565b6000610e9d60288361108b565b9150610ea8826111db565b604082019050919050565b6000610ebf8284610dd2565b915081905092915050565b6000610ed68284610e3c565b915081905092915050565b6000602082019050610ef66000830184610d8a565b92915050565b60006020820190508181036000830152610f168184610d99565b905092915050565b60006020820190508181036000830152610f388184610e03565b905092915050565b60006040820190508181036000830152610f5a8185610e03565b90508181036020830152610f6e8184610e03565b90509392505050565b60006060820190508181036000830152610f918186610e03565b90508181036020830152610fa58185610e03565b90508181036040830152610fb98184610e03565b9050949350505050565b60006020820190508181036000830152610fdc81610e6d565b9050919050565b60006020820190508181036000830152610ffc81610e90565b9050919050565b600061100d61101e565b9050611019828261111b565b919050565b6000604051905090565b600067ffffffffffffffff8211156110435761104261114c565b5b61104c8261117b565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600081905092915050565b60006110b2826110b9565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b838110156111065780820151818401526020810190506110eb565b83811115611115576000848401525b50505050565b6111248261117b565b810181811067ffffffffffffffff821117156111435761114261114c565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e00000000000000000000000000000000000000000000000000602082015250565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e2000000000000000000000000000000000000000000000000060208201525056fea2646970667358221220ef854efba8fa666e14c59062868b874c81e23e55df6701646a256b92444ab4d164736f6c63430008040033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file asset.sol. """
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
def create_domain(address):
    params = get_first_four_bytes_of_keccak(b"createDomain(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("burrow")  # domain name
    params = params + argument_encoding("user")  # default role
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
def create_asset(address):
    params = get_first_four_bytes_of_keccak(b"createAsset(string,string,string)")
    no_of_param = 3
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("cc")  # asset id
    params = params + argument_encoding("burrow")  # domain name
    params = params + argument_encoding("4")  #  precision
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
def get_asset(address):
    params = get_first_four_bytes_of_keccak(b"getAsset(string)")
    no_of_param = 1
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("cc#burrow")  # asset id
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
def add_asset(address):
    params = get_first_four_bytes_of_keccak(b"addAsset(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("cc#burrow")  # asset id
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
def subtract_asset(address):
    params = get_first_four_bytes_of_keccak(b"subtractAsset(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding("cc#burrow")  # asset id
    params = params + argument_encoding("300")  # amount of asset
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
def balance(address):
    params = get_first_four_bytes_of_keccak(b"queryBalance(string,string)")
    no_of_param = 2
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding(ADMIN_ACCOUNT_ID)  # account id
    params = params + argument_encoding("cc#burrow")  # asset id
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
create_domain(address)
create_asset(address)
hash = get_asset(address)
get_engine_receipts_result(hash)
add_asset(address)
hash = balance(address)
get_engine_receipts_result(hash)
subtract_asset(address)
hash = balance(address)
get_engine_receipts_result(hash)

print("done")
