// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.7.0 <0.9.0;

contract Transaction {
    address public serviceContractAddress;

    // Initializing service contract address in constructor
    constructor() {
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Queries the balance in _asset of an Iroha _account
    function getAccountTransactions(string memory _account, string memory _pageSize, string memory _firstTxHash, string memory _firstTxTime, string memory _lastTxTime, string memory _firstTxHeight, string memory _lastTxHeight, string memory _ordering) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAccountTransactions(string,string,string,string,string,string,string,string)",
            _account,
            _pageSize,
            _firstTxHash,
            _firstTxTime,
            _lastTxTime,
            _firstTxHeight,
            _lastTxHeight,
            _ordering);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    function getAccountAssetTransactions(string memory _account, string memory _asset, string memory _pageSize, string memory _firstTxHash, string memory _firstTxTime, string memory _lastTxTime, string memory _firstTxHeight, string memory _lastTxHeight, string memory _ordering) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAccountAssetTransactions(string,string,string,string,string,string,string,string,string)",
            _account,
            _asset,
            _pageSize,
            _firstTxHash,
            _firstTxTime,
            _lastTxTime,
            _firstTxHeight,
            _lastTxHeight,
            _ordering);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
    function getPendingTransactions(string memory _pageSize, string memory _firstTxHash, string memory _firstTxTime, string memory _lastTxTime, string memory _ordering) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getPendingTransactions(string,string,string,string,string)",
            _pageSize,
            _firstTxHash,
            _firstTxTime,
            _lastTxTime,
            _ordering);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    function getTransactions(string memory hash) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getTransactions(string)",
            hash);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}