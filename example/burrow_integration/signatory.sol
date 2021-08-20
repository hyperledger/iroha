// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract Signatory {
    address public serviceContractAddress;

    event AddedSignatory(string indexed name, string indexed key);
    event RemovedSignatory(string indexed name, string indexed key);

    // Initializing service contract address in constructor
    constructor(){
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Adds a signatory
    function addSignatory(string memory name, string memory key) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "addSignatory(string,string)",
            name,
            key);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit AddedSignatory(name, key);
        result = ret;
    }

    // Removes a signatory
    function removeSignatory(string memory name, string memory key) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "removeSignatory(string,string)",
            name,
            key);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit RemovedSignatory(name, key);
        result = ret;
    }

    // Gets signatories of account
    function getSignatories(string memory name) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getSignatories(string)",
            name);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }
}
