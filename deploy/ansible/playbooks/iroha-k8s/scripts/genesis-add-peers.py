#!/usr/env/python3
import json, csv, sys, base64
'''
peers.csv
host;port;priv_key_b64_encoded;pub_key_b64_encoded
'''

class Peer:
    def __init__(self, host, port, priv_key, pub_key):
        self.host = host
        self.port = port
        self.priv_key = priv_key
        self.pub_key = pub_key

def parse_peers(peers_csv_fp):
    peers = []
    with open(peers_csv_fp) as csvfile:
        peersreader = csv.reader(csvfile, delimiter=';')
        next(peersreader, None) # skip the header
        for peer in peersreader:
            peers.append(Peer(peer[0], peer[1], peer[3], peer[2]))
    return peers

def genesis_add_peers(peers_list, genesis_block_fp):
    with open(genesis_block_fp, 'r+') as genesis_json:
        genesis_dict = json.load(genesis_json)
        try:
            genesis_dict['blockV1']['payload']['transactions'][0]['payload']['reducedPayload']['commands'] = filter(lambda c: not c.get('addPeer'), genesis_dict['blockV1']['payload']['transactions'][0]['payload']['reducedPayload']['commands'])
        except KeyError:
            pass
        genesis_dict['blockV1']['payload']['transactions'][0]['payload']['reducedPayload']['commands'] = list(genesis_dict['blockV1']['payload']['transactions'][0]['payload']['reducedPayload']['commands'])
        for p in peers_list:
            p_add_command = {"addPeer": {"peer": {"address": "%s:%s" % (p.host, '10001'), "peerKey": p.pub_key}}}
            genesis_dict['blockV1']['payload']['transactions'][0]['payload']['reducedPayload']['commands'].append(p_add_command)
        genesis_json.seek(0)
        json.dump(genesis_dict, genesis_json, sort_keys=True)
        genesis_json.truncate()

def caliper_add_peers(peers_list, caliper_conf_fp):
    with open(caliper_conf_fp, 'r+') as caliper_conf_json:
        caliper_conf_dict = json.load(caliper_conf_json)
        try:
            caliper_conf_dict['iroha']['network'] = {}
        except KeyError:
            pass
        for i, p in enumerate(peers_list):
            p_node = {"node%s" % i: {"torii": "%s:%s" % (p.host, p.port)}}
            caliper_conf_dict['iroha']['network'].update(p_node)
        caliper_conf_json.seek(0)
        json.dump(caliper_conf_dict, caliper_conf_json, sort_keys=True)
        caliper_conf_json.truncate()

def caliper_rename_keys(priv_key_name, pub_key_name, caliper_conf_fp):
    with open(caliper_conf_fp, 'r+') as caliper_conf_json:
        caliper_conf_dict = json.load(caliper_conf_json)
        caliper_conf_dict['iroha']['admin']['key-pub'] = "network/iroha/simplenetwork/%s" % pub_key_name
        caliper_conf_dict['iroha']['admin']['key-priv'] = "network/iroha/simplenetwork/%s" % priv_key_name
        caliper_conf_json.seek(0)
        json.dump(caliper_conf_dict, caliper_conf_json, sort_keys=True)
        caliper_conf_json.truncate()

def to_b64(bytes_array):
    return base64.b64encode(bytes_array).decode('utf-8')

def print_keys_b64(peers):
    for peer in peers:
        priv_key = peer.priv_key.encode()
        pub_key = peer.pub_key.encode()
        print(to_b64(priv_key) + ',' + to_b64(pub_key))

if __name__ ==  "__main__":
    command = sys.argv[1]
    peers_csv = sys.argv[2]
    try:
        json_conf = sys.argv[3]
    except IndexError:
        pass
    peers = parse_peers(peers_csv)
    if command == 'add_iroha_peers':
        genesis_add_peers(peers, json_conf)
    elif command == 'add_caliper_peers':
        caliper_add_peers(peers, json_conf)
        caliper_rename_keys('admin-test.priv', 'admin-test.pub', json_conf)
    elif command == 'print_keys_b64':
        print_keys_b64(peers)
    else:
        print('Invalid command')
