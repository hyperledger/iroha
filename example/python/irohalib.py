#!/usr/bin/env python3
#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import ed25519
import hashlib
import binascii
import grpc
import time
import re
import os

import commands_pb2
import endpoint_pb2
import endpoint_pb2_grpc
import primitive_pb2
import queries_pb2
import transaction_pb2


class IrohaCrypto(object):
    """
    Collection of general crypto-related functions
    """

    @staticmethod
    def derive_public_key(private_key):
        """
        Calculate public key from private key
        :param private_key: hex encoded private key
        :return: hex encoded public key
        """
        secret = binascii.unhexlify(private_key)
        public_key = ed25519.publickey_unsafe(secret)
        hex_public_key = binascii.hexlify(public_key)
        return hex_public_key

    @staticmethod
    def hash(proto_with_payload):
        """
        Calculates hash of payload of proto message
        :proto_with_payload: proto transaction or query
        :return: bytes representation of hash
        """
        obj = None
        if hasattr(proto_with_payload, 'payload'):
            obj = getattr(proto_with_payload, 'payload')
        # hash of meta is implemented for block streaming queries,
        # because they do not have a payload in their schema
        elif hasattr(proto_with_payload, 'meta'):
            obj = getattr(proto_with_payload, 'meta')

        bytes = obj.SerializeToString()
        hash = hashlib.sha3_256(bytes).digest()
        return hash

    @staticmethod
    def _signature(message, private_key):
        """
        Calculate signature for given message and private key
        :param message: proto that has payload message inside
        :param private_key: hex string with private key
        :return: a proto Signature message
        """
        public_key = IrohaCrypto.derive_public_key(private_key)
        sk = binascii.unhexlify(private_key)
        pk = binascii.unhexlify(public_key)
        message_hash = IrohaCrypto.hash(message)
        signature_bytes = ed25519.signature_unsafe(message_hash, sk, pk)
        signature = primitive_pb2.Signature()
        signature.public_key = public_key
        signature.signature = binascii.hexlify(signature_bytes)
        return signature

    @staticmethod
    def sign_transaction(transaction, *private_keys):
        """
        Add specified signatures to a transaction. Source transaction will be modified
        :param transaction: the transaction to be signed
        :param private_keys: hex strings of private keys to sign the transaction
        :return: the modified transaction
        """
        assert len(private_keys), 'At least one private key has to be passed'
        signatures = []
        for private_key in private_keys:
            signature = IrohaCrypto._signature(transaction, private_key)
            signatures.append(signature)
        transaction.signatures.extend(signatures)
        return transaction

    @staticmethod
    def sign_query(query, private_key):
        """
        Add a signature to a query. Source query will be modified
        :param query: the query to be signed
        :param private_key: hex string of private key to sign the query
        :return: the modified query
        """
        signature = IrohaCrypto._signature(query, private_key)
        query.signature.CopyFrom(signature)
        return query

    @staticmethod
    def reduced_hash(transaction):
        """
        Calculates hash of reduced payload of a transaction
        :param transaction: transaction to be processed
        :return: hex representation of hash
        """
        bytes = transaction.payload.reduced_payload.SerializeToString()
        hash = hashlib.sha3_256(bytes).digest()
        hex_hash = binascii.hexlify(hash)
        return hex_hash

    @staticmethod
    def private_key():
        """
        Generates new random private key
        :return: hex representation of private key
        """
        return binascii.b2a_hex(os.urandom(32))


class Iroha(object):
    """
    Collection of factory methods for transactions and queries creation
    """

    def __init__(self, creator_account=None):
        self.creator_account = creator_account

    @staticmethod
    def _camel_case_to_snake_case(camel_case_string):
        """Transforms"""
        tmp = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camel_case_string)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', tmp).lower()

    @staticmethod
    def now():
        """Current timestamp in milliseconds"""
        return int(round(time.time() * 1000))

    def transaction(self, commands, quorum=1, creator_account=None, created_time=None):
        """
        Creates a protobuf transaction with specified set of entities
        :param commands: list of commands generated via command factory method
        :param quorum: required number of signatures, 1 is default
        :param creator_account: id of transaction creator account
        :param created_time: transaction creation timestamp in milliseconds
        :return: a proto transaction
        """
        assert creator_account or self.creator_account, "No account name specified as transaction creator id"
        if not created_time:
            created_time = self.now()
        if not creator_account:
            creator_account = self.creator_account
        tx = transaction_pb2.Transaction()
        core_payload = tx.payload.reduced_payload
        # setting transaction contents
        core_payload.quorum = quorum
        core_payload.created_time = created_time
        core_payload.creator_account_id = creator_account
        core_payload.commands.extend(commands)
        return tx

    @staticmethod
    def command(name, **kwargs):
        """
        Creates a protobuf command to be inserted into a transaction
        :param name: CamelCased name of command
        :param kwargs: command arguments as they defined in schema
        :return: a proto command

        Usage example:
        cmd = Iroha.command('CreateDomain', domain_id='test', default_role='user')
        """
        command_wrapper = commands_pb2.Command()
        field_name = Iroha._camel_case_to_snake_case(name)
        internal_command = getattr(command_wrapper, field_name)
        for key, value in kwargs.items():
            if 'permissions' == key:
                permissions_attr = getattr(internal_command, key)
                permissions_attr.extend(value)
                continue
            if 'peer' == key:
                peer_attr = getattr(internal_command, key)
                peer_attr.CopyFrom(value)
                continue
            setattr(internal_command, key, value)
        return command_wrapper

    def query(self, name, counter=1, creator_account=None, created_time=None, page_size=None, first_tx_hash=None,
              **kwargs):
        """
        Creates a protobuf query with specified set of entities
        :param name: CamelCased name of query to be executed
        :param counter: query counter, should be incremented for each new query
        :param creator_account: account id of query creator
        :param created_time: query creation timestamp in milliseconds
        :param page_size: a non-zero positive number, size of result rowset for queries with pagination
        :param first_tx_hash: optional hash of a transaction that will be the beginning of the next page
        :param kwargs: query arguments as they defined in schema
        :return: a proto query
        """
        assert creator_account or self.creator_account, "No account name specified as query creator id"
        pagination_meta = None
        if not created_time:
            created_time = self.now()
        if not creator_account:
            creator_account = self.creator_account
        if page_size or first_tx_hash:
            pagination_meta = queries_pb2.TxPaginationMeta()
            pagination_meta.page_size = page_size
            if first_tx_hash:
                pagination_meta.first_tx_hash = first_tx_hash

        meta = queries_pb2.QueryPayloadMeta()
        meta.created_time = created_time
        meta.creator_account_id = creator_account
        meta.query_counter = counter

        query_wrapper = queries_pb2.Query()
        query_wrapper.payload.meta.CopyFrom(meta)
        field_name = Iroha._camel_case_to_snake_case(name)
        internal_query = getattr(query_wrapper.payload, field_name)
        for key, value in kwargs.items():
            if 'tx_hashes' == key:
                hashes_attr = getattr(internal_query, key)
                hashes_attr.extend(value)
                continue
            setattr(internal_query, key, value)
        if pagination_meta:
            pagination_meta_attr = getattr(internal_query, 'pagination_meta')
            pagination_meta_attr.CopyFrom(pagination_meta)
        if not len(kwargs):
            message = getattr(queries_pb2, name)()
            internal_query.CopyFrom(message)
        return query_wrapper

    def blocks_query(self, counter=1, creator_account=None, created_time=None):
        """
        Creates a protobuf query for a blocks stream
        :param counter: query counter, should be incremented for each new query
        :param creator_account: account id of query creator
        :param created_time: query creation timestamp in milliseconds
        :return: a proto blocks query
        """
        if not created_time:
            created_time = self.now()
        if not creator_account:
            creator_account = self.creator_account

        meta = queries_pb2.QueryPayloadMeta()
        meta.created_time = created_time
        meta.creator_account_id = creator_account
        meta.query_counter = counter

        query_wrapper = queries_pb2.BlocksQuery()
        query_wrapper.meta.CopyFrom(meta)
        return query_wrapper

    @staticmethod
    def batch(*transactions, atomic=True):
        """
        Tie transactions to be a single batch. All of them will have a common batch meta.
        :param transactions: list of transactions to be tied into a batch
        :param atomic: boolean - prescribes type of batch: ATOMIC if true, otherwise - ORDERED
        :return: nothing, source transactions will be modified
        """
        meta_ref = transaction_pb2.Transaction.Payload.BatchMeta
        batch_type = meta_ref.ATOMIC if atomic else meta_ref.ORDERED
        reduced_hashes = []
        for transaction in transactions:
            reduced_hash = IrohaCrypto.reduced_hash(transaction)
            reduced_hashes.append(reduced_hash)
        meta = meta_ref()
        meta.type = batch_type
        meta.reduced_hashes.extend(reduced_hashes)
        for transaction in transactions:
            transaction.payload.batch.CopyFrom(meta)


class IrohaGrpc(object):
    """
    Possible implementation of gRPC transport to Iroha
    """

    def __init__(self, address=None):
        self._address = address if address else '127.0.0.1:50051'
        self._channel = grpc.insecure_channel(self._address)
        self._command_service_stub = endpoint_pb2_grpc.CommandService_v1Stub(
            self._channel)
        self._query_service_stub = endpoint_pb2_grpc.QueryService_v1Stub(
            self._channel)

    def send_tx(self, transaction):
        """
        Send a transaction to Iroha
        :param transaction: protobuf Transaction
        :return: None
        """
        code = grpc.StatusCode.OK
        try:
            self._command_service_stub.Torii(transaction)
        except grpc.RpcError as error:
            code = error.code()
            print('Error occurred inside send_tx:', error)
        return code

    def send_txs(self, *transactions):
        """
        Send a series of transactions to Iroha at once.
        Useful for submitting batches of transactions.
        :param transactions: protobuf transactions to be sent
        :return: None
        """
        tx_list = endpoint_pb2.TxList()
        tx_list.transactions.extend(transactions)
        code = grpc.StatusCode.OK
        try:
            self._command_service_stub.ListTorii(tx_list)
        except grpc.RpcError as error:
            code = error.code()
            print('Error occurred inside send_txs:', error)
        return code

    def send_query(self, query):
        """
        Send a query to Iroha
        :param query: protobuf Query
        :return: a protobuf response to the query
        :raise: grpc.RpcError with .code() available in case of any error
        """
        response = self._query_service_stub.Find(query)
        return response

    def send_blocks_stream_query(self, query):
        """
        Send a query for blocks stream to Iroha
        :param query: protobuf BlocksQuery
        :return: an iterable over a stream of blocks
        :raise: grpc.RpcError with .code() available in case of any error
        """
        response = self._query_service_stub.FetchCommits(query)
        for block in response:
            yield block

    def tx_status(self, transaction):
        """
        Request a status of a transaction
        :param transaction: the transaction, which status is about to be known
        :return: a tuple with the symbolic status description,
        integral status code, and error message string (will be empty if no error occurred)
        """
        request = endpoint_pb2.TxStatusRequest()
        request.tx_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
        response = self._command_service_stub.Status(request)
        status_code = response.tx_status
        status_name = endpoint_pb2.TxStatus.Name(response.tx_status)
        error_message = response.error_message
        return status_name, status_code, error_message

    def tx_status_stream(self, transaction):
        """
        Generator of transaction statuses from status stream
        :param transaction: the transaction, which status is about to be known
        :return: an iterable over a series of tuples with symbolic status description,
        integral status code, and error message string (will be empty if no error occurred)
        """
        request = endpoint_pb2.TxStatusRequest()
        request.tx_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
        response = self._command_service_stub.StatusStream(request)
        for status in response:
            status_name = endpoint_pb2.TxStatus.Name(status.tx_status)
            status_code = status.tx_status
            error_code = status.error_code
            yield status_name, status_code, error_code
