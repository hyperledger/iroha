#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import json
import os

from . import kv_schema_pb2

MAX_SIZE = 1000

_save_file_path = str()
_persistent_kv_storage = dict()
_block_kv_storage = dict()
_tx_kv_storage = dict()


def get_supported_data_model_ids():
    return [('test_kv', '0.1.0')]


def execute(cmd_serialized: memoryview):
    cmd = kv_schema_pb2.Command()
    cmd.ParseFromString(cmd_serialized)
    which = cmd.payload.WhichOneof('command')
    global _tx_kv_storage
    if which == 'set':
        key = cmd.payload.set.key
        val = cmd.payload.set.value
        if not key in _tx_kv_storage:
            if len(_tx_kv_storage) >= MAX_SIZE:
                return (3, "storage limit exceeded")
        _tx_kv_storage[key] = val
        print(f'storage[{key}] is set to {val}')
        return None
    elif which == 'nuke':
        _tx_kv_storage.clear()
        print(f'storage cleared')
        return None


def commit_transaction():
    global _tx_kv_storage
    global _block_kv_storage
    _block_kv_storage = _tx_kv_storage.copy()


def commit_block():
    commit_transaction()
    global _block_kv_storage
    global _persistent_kv_storage
    _persistent_kv_storage = _block_kv_storage.copy()
    _save_persistent()


def rollback_transaction():
    global _tx_kv_storage
    global _block_kv_storage
    _tx_kv_storage = _block_kv_storage.copy()


def rollback_block():
    global _block_kv_storage
    global _persistent_kv_storage
    _block_kv_storage = _persistent_kv_storage.copy()
    rollback_transaction()


def _save_persistent():
    global _save_file_path
    global _persistent_kv_storage
    with open(_save_file_path, 'wt') as out:
        json.dump(_persistent_kv_storage, out)
    print(f'saved persistent data to {_save_file_path}')


def _load_persistent():
    global _save_file_path
    global _tx_kv_storage
    global _block_kv_storage
    global _persistent_kv_storage
    if (os.path.isfile(_save_file_path)):
        with open(_save_file_path, 'rt') as inp:
            _persistent_kv_storage = json.load(inp)
        _block_kv_storage = _persistent_kv_storage.copy()
        _tx_kv_storage = _persistent_kv_storage.copy()


def initialize(save_file_path: str):
    global _save_file_path
    _save_file_path = save_file_path
    _load_persistent()
