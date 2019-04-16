'''
This script will parse Iroha block and form a markdown file with accounts, assets, domains, roles tables.
Markdown file will be saved locally in the same folder  
'''
import sys
import block_pb2
import primitive_pb2
from google.protobuf import json_format

import json
import pytablewriter

if len(sys.argv) != 2:
    print("Add genesis block path")
    exit(1)

with open(sys.argv[1]) as f:
    data = json.load(f)

json_str = json.dumps(data)
parsed_block = json_format.Parse(json_str, block_pb2.Block(), ignore_unknown_fields=True)

tx_num = len(parsed_block.payload.transactions)

domain_writer = pytablewriter.MarkdownTableWriter()
domain_writer.table_name = "Domains"
domain_writer.header_list = ["Domain id", "Default Role"]

role_writer = pytablewriter.MarkdownTableWriter()
role_writer.table_name = "Roles"
role_writer.header_list = ["Role Name", "Permissions"]

acc_writer = pytablewriter.MarkdownTableWriter()
acc_writer.table_name = "Accounts"
acc_writer.header_list = ["Account id", "Roles", "All permissions"]

assets = []
domains = {}
roles = {}
accounts = {}

d_wr = []
r_wr = []
ac_wr = []

name_by_val = primitive_pb2._ROLEPERMISSION.values_by_number

for i in range(tx_num):
    tx = parsed_block.payload.transactions[i]
    tx_commands = tx.payload.reduced_payload.commands
    for com in tx_commands:
        if com.HasField("create_asset"):
            assets.append(
                [str(com.create_asset.asset_name) + "#" + str(com.create_asset.domain_id), com.create_asset.precision])
        if com.HasField("create_domain"):
            domains[str(com.create_domain.domain_id)] = str(com.create_domain.default_role)
            d_wr.append([str(com.create_domain.domain_id), str(com.create_domain.default_role)])
        if com.HasField("create_role"):
            perms = [str(name_by_val[x].name) for x in com.create_role.permissions]
            perm_string = ', \n\n'.join(map(str, perms))
            roles[str(com.create_role.role_name)] = perms
            r_wr.append([str(com.create_role.role_name), perm_string])
        if com.HasField("create_account"):
            acc_id = com.create_account.account_name + "@" + com.create_account.domain_id
            # User default role
            def_role = domains[com.create_account.domain_id]
            perms_set = set(roles[def_role])
            accounts[acc_id] = ([def_role], perms_set)
        if com.HasField("append_role"):
            acc_id = com.append_role.account_id
            role = com.append_role.role_name
            accounts[acc_id][0].append(role)
            accounts[acc_id][1].update(roles[role])

for acc in accounts.keys():
    str1 = ", \n\n".join(list(accounts[acc][0]))
    perms_sort = sorted(accounts[acc][1])
    ac_wr.append([acc, str1, ", \n\n".join(perms_sort)])

# Account
acc_writer.value_matrix = ac_wr
acc_table = acc_writer.dumps()

# Domains
domain_writer.value_matrix = d_wr
domain_table = domain_writer.dumps()

# Assets
asts_writer = pytablewriter.MarkdownTableWriter()
asts_writer.table_name = "Assets"
asts_writer.header_list = ["Asset id", "Precision:"]
asts_writer.value_matrix = assets
ast_table = asts_writer.dumps()

# Roles
role_writer.value_matrix = r_wr
role_domain = role_writer.dumps()

with open("genesis.md", "w") as f:
    f.write(domain_table)
    f.write(ast_table)
    f.write(role_domain)
    f.write(acc_table)
