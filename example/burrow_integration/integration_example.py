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
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610f90806100746000396000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c80632c74aaaf1461005c5780632cddc4111461008c57806337410dfa146100bc578063bc53c0c4146100ec578063d4e804ab1461011c575b600080fd5b61007660048036038101906100719190610893565b61013a565b6040516100839190610bcb565b60405180910390f35b6100a660048036038101906100a19190610996565b6102a9565b6040516100b39190610bcb565b60405180910390f35b6100d660048036038101906100d19190610893565b610481565b6040516100e39190610bcb565b60405180910390f35b610106600480360381019061010191906108ff565b61063d565b6040516101139190610bcb565b60405180910390f35b610124610807565b6040516101319190610bb0565b60405180910390f35b606060008383604051602401610151929190610c0f565b6040516020818303038152906040527f260b5d52000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516102189190610b82565b600060405180830381855af49150503d8060008114610253576040519150601f19603f3d011682016040523d82523d6000602084013e610258565b606091505b50915091508161029d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161029490610d13565b60405180910390fd5b80935050505092915050565b60606000858585856040516024016102c49493929190610c92565b6040516020818303038152906040527f2cddc411000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161038b9190610b82565b600060405180830381855af49150503d80600081146103c6576040519150601f19603f3d011682016040523d82523d6000602084013e6103cb565b606091505b509150915081610410576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161040790610cf3565b60405180910390fd5b8660405161041e9190610b99565b6040518091039020886040516104349190610b99565b60405180910390207f6a739057159b3f3e2efcba00d44b0fa47de56972ed8776a2da7682bcf7c67de18760405161046b9190610bed565b60405180910390a3809350505050949350505050565b606060008383604051602401610498929190610c0f565b6040516020818303038152906040527f37410dfa000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161055f9190610b82565b600060405180830381855af49150503d806000811461059a576040519150601f19603f3d011682016040523d82523d6000602084013e61059f565b606091505b5091509150816105e4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105db90610cf3565b60405180910390fd5b856040516105f29190610b99565b60405180910390207fd8ea495c3185a632d25d8ccc5c355aeb4058bfaaaee8647c075dc5c1ce62914c866040516106299190610bed565b60405180910390a280935050505092915050565b6060600084848460405160240161065693929190610c46565b6040516020818303038152906040527fbc53c0c4000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161071d9190610b82565b600060405180830381855af49150503d8060008114610758576040519150601f19603f3d011682016040523d82523d6000602084013e61075d565b606091505b5091509150816107a2576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161079990610cf3565b60405180910390fd5b856040516107b09190610b99565b6040518091039020876040516107c69190610b99565b60405180910390207fb4086b7a9e5eac405225b6c630a4147f0a8dcb4af3583733b10db7b91ad21ffd60405160405180910390a38093505050509392505050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600061083e61083984610d58565b610d33565b90508281526020810184848401111561085657600080fd5b610861848285610e09565b509392505050565b600082601f83011261087a57600080fd5b813561088a84826020860161082b565b91505092915050565b600080604083850312156108a657600080fd5b600083013567ffffffffffffffff8111156108c057600080fd5b6108cc85828601610869565b925050602083013567ffffffffffffffff8111156108e957600080fd5b6108f585828601610869565b9150509250929050565b60008060006060848603121561091457600080fd5b600084013567ffffffffffffffff81111561092e57600080fd5b61093a86828701610869565b935050602084013567ffffffffffffffff81111561095757600080fd5b61096386828701610869565b925050604084013567ffffffffffffffff81111561098057600080fd5b61098c86828701610869565b9150509250925092565b600080600080608085870312156109ac57600080fd5b600085013567ffffffffffffffff8111156109c657600080fd5b6109d287828801610869565b945050602085013567ffffffffffffffff8111156109ef57600080fd5b6109fb87828801610869565b935050604085013567ffffffffffffffff811115610a1857600080fd5b610a2487828801610869565b925050606085013567ffffffffffffffff811115610a4157600080fd5b610a4d87828801610869565b91505092959194509250565b610a6281610dd7565b82525050565b6000610a7382610d89565b610a7d8185610d9f565b9350610a8d818560208601610e18565b610a9681610eab565b840191505092915050565b6000610aac82610d89565b610ab68185610db0565b9350610ac6818560208601610e18565b80840191505092915050565b6000610add82610d94565b610ae78185610dbb565b9350610af7818560208601610e18565b610b0081610eab565b840191505092915050565b6000610b1682610d94565b610b208185610dcc565b9350610b30818560208601610e18565b80840191505092915050565b6000610b49602783610dbb565b9150610b5482610ebc565b604082019050919050565b6000610b6c602883610dbb565b9150610b7782610f0b565b604082019050919050565b6000610b8e8284610aa1565b915081905092915050565b6000610ba58284610b0b565b915081905092915050565b6000602082019050610bc56000830184610a59565b92915050565b60006020820190508181036000830152610be58184610a68565b905092915050565b60006020820190508181036000830152610c078184610ad2565b905092915050565b60006040820190508181036000830152610c298185610ad2565b90508181036020830152610c3d8184610ad2565b90509392505050565b60006060820190508181036000830152610c608186610ad2565b90508181036020830152610c748185610ad2565b90508181036040830152610c888184610ad2565b9050949350505050565b60006080820190508181036000830152610cac8187610ad2565b90508181036020830152610cc08186610ad2565b90508181036040830152610cd48185610ad2565b90508181036060830152610ce88184610ad2565b905095945050505050565b60006020820190508181036000830152610d0c81610b3c565b9050919050565b60006020820190508181036000830152610d2c81610b5f565b9050919050565b6000610d3d610d4e565b9050610d498282610e4b565b919050565b6000604051905090565b600067ffffffffffffffff821115610d7357610d72610e7c565b5b610d7c82610eab565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600081905092915050565b6000610de282610de9565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b83811015610e36578082015181840152602081019050610e1b565b83811115610e45576000848401525b50505050565b610e5482610eab565b810181811067ffffffffffffffff82111715610e7357610e72610e7c565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e00000000000000000000000000000000000000000000000000602082015250565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e2000000000000000000000000000000000000000000000000060208201525056fea264697066735822122097d0915acf0fba6aaeec5068f9bf82acdbdce6d684729b0af81f55ee2929be6664736f6c63430008040033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file iroha.sol. """
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
    ascii_string = bytes_object.decode("ASCII")
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
    params = params + argument_encoding("test4")  # source account id
    params = params + argument_encoding("test")  # domain id
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
def transfer(address):
    params = get_first_four_bytes_of_keccak(
        b"transferAsset(string,string,string,string)"
    )
    no_of_param = 4
    for x in range(no_of_param):
        params = params + left_padded_address_of_param(x, no_of_param)
    params = params + argument_encoding(ADMIN_ACCOUNT_ID)  # source account
    params = params + argument_encoding("userone@domain")  # destination account
    params = params + argument_encoding("coin#domain")  # asset id
    params = params + argument_encoding("100")  # amount of asset
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
    params = params + argument_encoding("coin#domain")  # asset id
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
hash = balance(address)
get_engine_receipts_result(hash)
add_asset(address)
hash = balance(address)
get_engine_receipts_result(hash)
transfer(address)
hash = balance(address)
get_engine_receipts_result(hash)
hash = create_account(address)
get_engine_receipts_result(hash)

print("done")
