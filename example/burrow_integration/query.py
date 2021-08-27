import os
import binascii
from iroha import IrohaCrypto
from iroha import Iroha, IrohaGrpc
import sys
from Crypto.Hash import keccak
import integration_helpers

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


@integration_helpers.trace
def create_contract():
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610ae5806100746000396000f3fe608060405234801561001057600080fd5b50600436106100565760003560e01c80622f5bc01461005b57806359bea24e1461008b57806371061398146100bb578063cd559561146100d9578063d4e804ab146100f7575b600080fd5b61007560048036038101906100709190610736565b610115565b604051610082919061087e565b60405180910390f35b6100a560048036038101906100a09190610736565b610280565b6040516100b2919061087e565b60405180910390f35b6100c36103ec565b6040516100d0919061087e565b60405180910390f35b6100e161054b565b6040516100ee919061087e565b60405180910390f35b6100ff6106aa565b60405161010c9190610863565b60405180910390f35b606060008260405160240161012a91906108a0565b6040516020818303038152906040527e2f5bc0000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516101f0919061084c565b600060405180830381855af49150503d806000811461022b576040519150601f19603f3d011682016040523d82523d6000602084013e610230565b606091505b509150915081610275576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161026c906108c2565b60405180910390fd5b809350505050919050565b606060008260405160240161029591906108a0565b6040516020818303038152906040527f59bea24e000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161035c919061084c565b600060405180830381855af49150503d8060008114610397576040519150601f19603f3d011682016040523d82523d6000602084013e61039c565b606091505b5091509150816103e1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103d8906108c2565b60405180910390fd5b809350505050919050565b606060006040516024016040516020818303038152906040527f71061398000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516104bd919061084c565b600060405180830381855af49150503d80600081146104f8576040519150601f19603f3d011682016040523d82523d6000602084013e6104fd565b606091505b509150915081610542576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610539906108c2565b60405180910390fd5b80935050505090565b606060006040516024016040516020818303038152906040527fcd559561000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161061c919061084c565b600060405180830381855af49150503d8060008114610657576040519150601f19603f3d011682016040523d82523d6000602084013e61065c565b606091505b5091509150816106a1576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610698906108c2565b60405180910390fd5b80935050505090565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60006106e16106dc84610907565b6108e2565b9050828152602081018484840111156106f957600080fd5b6107048482856109ad565b509392505050565b600082601f83011261071d57600080fd5b813561072d8482602086016106ce565b91505092915050565b60006020828403121561074857600080fd5b600082013567ffffffffffffffff81111561076257600080fd5b61076e8482850161070c565b91505092915050565b6107808161097b565b82525050565b600061079182610938565b61079b818561094e565b93506107ab8185602086016109bc565b6107b481610a4f565b840191505092915050565b60006107ca82610938565b6107d4818561095f565b93506107e48185602086016109bc565b80840191505092915050565b60006107fb82610943565b610805818561096a565b93506108158185602086016109bc565b61081e81610a4f565b840191505092915050565b600061083660278361096a565b915061084182610a60565b604082019050919050565b600061085882846107bf565b915081905092915050565b60006020820190506108786000830184610777565b92915050565b600060208201905081810360008301526108988184610786565b905092915050565b600060208201905081810360008301526108ba81846107f0565b905092915050565b600060208201905081810360008301526108db81610829565b9050919050565b60006108ec6108fd565b90506108f882826109ef565b919050565b6000604051905090565b600067ffffffffffffffff82111561092257610921610a20565b5b61092b82610a4f565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b60006109868261098d565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b838110156109da5780820151818401526020810190506109bf565b838111156109e9576000848401525b50505050565b6109f882610a4f565b810181811067ffffffffffffffff82111715610a1757610a16610a20565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e0000000000000000000000000000000000000000000000000060208201525056fea2646970667358221220ec72f3b3f2061603a61400bade159313cfaa93d70a3c7b7f170d62cf2827a91064736f6c63430008040033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file query.sol. """
    tx = iroha.transaction(
        [iroha.command("CallEngine", caller=ADMIN_ACCOUNT_ID, input=bytecode)]
    )
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    net.send_tx(tx)
    hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
    for status in net.tx_status_stream(tx):
        print(status)
    return hex_hash


@integration_helpers.trace
def get_peers(address):
    params = integration_helpers.get_first_four_bytes_of_keccak(b"getPeers()")
    no_of_param = 0
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


@integration_helpers.trace
def get_block(address):
    params = integration_helpers.get_first_four_bytes_of_keccak(b"getBlock(string)")
    no_of_param = 1
    for x in range(no_of_param):
        params = params + integration_helpers.left_padded_address_of_param(
            x, no_of_param
        )
    params = params + integration_helpers.argument_encoding("10")  # block height
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


@integration_helpers.trace
def get_roles(address):
    params = integration_helpers.get_first_four_bytes_of_keccak(b"getRoles()")
    no_of_param = 0
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


@integration_helpers.trace
def get_role_permissions(address):
    params = integration_helpers.get_first_four_bytes_of_keccak(
        b"getRolePermissions(string)"
    )
    no_of_param = 1
    for x in range(no_of_param):
        params = params + integration_helpers.left_padded_address_of_param(
            x, no_of_param
        )
    params = params + integration_helpers.argument_encoding("money_creator")  # role id
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
address = integration_helpers.get_engine_receipts_address(hash)
hash = get_peers(address)
integration_helpers.get_engine_receipts_result(hash)
hash = get_block(address)
integration_helpers.get_engine_receipts_result(hash)
hash = get_roles(address)
integration_helpers.get_engine_receipts_result(hash)
hash = get_role_permissions(address)
integration_helpers.get_engine_receipts_result(hash)

print("done")
