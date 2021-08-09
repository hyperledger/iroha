// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract DetailAccount {
    address public serviceContractAddress;

    event Updated(string indexed name, string indexed key, string indexed value);

    // Initializing service contract address in constructor
    constructor(){
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Queries the balance in _asset of an Iroha _account
    function setDetail(string memory name, string memory key, string memory value) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "setDetail(string,string,string)",
            name,
            key,
            value);
        (bool success, bytes memory ret) =
            address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");

        emit Updated(name, key, value);
        result = ret;
    }

    function getDetail() public returns (bytes memory result) {
         bytes memory payload = abi.encodeWithSignature(
            "getDetail()");
        (bool success, bytes memory ret) =
            address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");

        result = ret;
    }
}