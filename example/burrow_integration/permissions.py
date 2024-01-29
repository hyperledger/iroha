import os
import binascii
from iroha import IrohaCrypto
from iroha import Iroha, IrohaGrpc
from iroha.primitive_pb2 import can_set_my_account_detail
import sys
from Crypto.Hash import keccak
import integration_helpers
import json
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
    bytecode = "608060405234801561001057600080fd5b5073a6abc17819738299b3b2c1ce46d55c74f04e290c6000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506109ef806100746000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c80632808235f14610051578063ac5f9fd014610081578063d2192dbf146100b1578063d4e804ab146100e1575b600080fd5b61006b600480360381019061006691906105e0565b6100ff565b604051610078919061075f565b60405180910390f35b61009b600480360381019061009691906105e0565b61026e565b6040516100a8919061075f565b60405180910390f35b6100cb60048036038101906100c691906105e0565b6103dd565b6040516100d8919061075f565b60405180910390f35b6100e961054c565b6040516100f69190610744565b60405180910390f35b606060008383604051602401610116929190610781565b6040516020818303038152906040527f2808235f000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516101dd919061072d565b600060405180830381855af49150503d8060008114610218576040519150601f19603f3d011682016040523d82523d6000602084013e61021d565b606091505b509150915081610262576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610259906107b8565b60405180910390fd5b80935050505092915050565b606060008383604051602401610285929190610781565b6040516020818303038152906040527fac5f9fd0000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360405161034c919061072d565b600060405180830381855af49150503d8060008114610387576040519150601f19603f3d011682016040523d82523d6000602084013e61038c565b606091505b5091509150816103d1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103c8906107b8565b60405180910390fd5b80935050505092915050565b6060600083836040516024016103f4929190610781565b6040516020818303038152906040527fd2192dbf000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060008060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16836040516104bb919061072d565b600060405180830381855af49150503d80600081146104f6576040519150601f19603f3d011682016040523d82523d6000602084013e6104fb565b606091505b509150915081610540576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610537906107b8565b60405180910390fd5b80935050505092915050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600061058361057e846107fd565b6107d8565b90508281526020810184848401111561059f5761059e61094a565b5b6105aa8482856108a3565b509392505050565b600082601f8301126105c7576105c6610945565b5b81356105d7848260208601610570565b91505092915050565b600080604083850312156105f7576105f6610954565b5b600083013567ffffffffffffffff8111156106155761061461094f565b5b610621858286016105b2565b925050602083013567ffffffffffffffff8111156106425761064161094f565b5b61064e858286016105b2565b9150509250929050565b61066181610871565b82525050565b60006106728261082e565b61067c8185610844565b935061068c8185602086016108b2565b61069581610959565b840191505092915050565b60006106ab8261082e565b6106b58185610855565b93506106c58185602086016108b2565b80840191505092915050565b60006106dc82610839565b6106e68185610860565b93506106f68185602086016108b2565b6106ff81610959565b840191505092915050565b6000610717602783610860565b91506107228261096a565b604082019050919050565b600061073982846106a0565b915081905092915050565b60006020820190506107596000830184610658565b92915050565b600060208201905081810360008301526107798184610667565b905092915050565b6000604082019050818103600083015261079b81856106d1565b905081810360208301526107af81846106d1565b90509392505050565b600060208201905081810360008301526107d18161070a565b9050919050565b60006107e26107f3565b90506107ee82826108e5565b919050565b6000604051905090565b600067ffffffffffffffff82111561081857610817610916565b5b61082182610959565b9050602081019050919050565b600081519050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600061087c82610883565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b82818337600083830152505050565b60005b838110156108d05780820151818401526020810190506108b5565b838111156108df576000848401525b50505050565b6108ee82610959565b810181811067ffffffffffffffff8211171561090d5761090c610916565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600080fd5b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4572726f722063616c6c696e67207365727669636520636f6e7472616374206660008201527f756e6374696f6e0000000000000000000000000000000000000000000000000060208201525056fea2646970667358221220ff48c720bd6f91e2287a842e1073c8797fe49f32f6ec1277657816f496b302e464736f6c63430008070033"
    """Bytecode was generated using remix editor  https://remix.ethereum.org/ from file permissions.sol. """
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
def grant_permission(address, permission):
    params = integration_helpers.get_first_four_bytes_of_keccak(
        b"grantPermission(string,string)"
    )
    no_of_param = 2
    for x in range(no_of_param):
        params = params + integration_helpers.left_padded_address_of_param(
            x, no_of_param
        )
    params = params + integration_helpers.argument_encoding(ADMIN_ACCOUNT_ID)  # account id
    params = params + integration_helpers.argument_encoding(permission)  # permission
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
def revoke_permission(address, permission):
    params = integration_helpers.get_first_four_bytes_of_keccak(
        b"revokePermission(string,string)"
    )
    no_of_param = 2
    for x in range(no_of_param):
        params = params + integration_helpers.left_padded_address_of_param(
            x, no_of_param
        )
    params = params + integration_helpers.argument_encoding(ADMIN_ACCOUNT_ID)  # account id
    params = params + integration_helpers.argument_encoding(permission)  # permission
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
def create_role(address, role_name, permissions):
    params = integration_helpers.get_first_four_bytes_of_keccak(
        b"createRole(string,string)"
    )
    no_of_param = 2
    for x in range(no_of_param):
        params = params + integration_helpers.left_padded_address_of_param(
            x, no_of_param
        )
    params = params + integration_helpers.argument_encoding(role_name)  # role
    params = params + integration_helpers.argument_encoding(permissions)  # permissions (json formatted)
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
def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    print('Transaction hash = {}, creator = {}'.format(
        hex_hash, transaction.payload.reduced_payload.creator_account_id))
    net.send_tx(transaction)
    for status in net.tx_status_stream(transaction):
        print(status)
hash = create_contract()
address = integration_helpers.get_engine_receipts_address(hash)
grant_permission(address, 'can_get_peers')
revoke_permission(address, 'can_get_peers')
create_role(address, 'my_cool_role','["can_receive", "can_transfer"]')
