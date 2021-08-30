// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.9.0;

contract SetupAccount {
    address public serviceContractAddress;

    event CreatedAccount(string indexed name, string indexed domain);
    event AddedSignatory(string indexed name, string indexed key);
    event RemovedSignatory(string indexed name, string indexed key);
    event Transferred(string indexed source, string indexed destination, string amount);
    event Updated(string indexed name, string indexed key, string indexed value);
    event CreatedAsset(string indexed name,string indexed domain, string indexed precision);
    event AddedAmount(string indexed asset, string amount);
    event SubtractedAmount(string indexed asset, string amount);

    // Initializing service contract address in constructor
    constructor(){
        serviceContractAddress = 0xA6Abc17819738299B3B2c1CE46d55c74f04E290C;
    }

    // Queries the balance in _asset of an Iroha _account
    function createAccount(string memory name, string memory domain, string memory key) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "createAccount(string,string,string)",
            name,
            domain,
            key);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit CreatedAccount(name, domain);
        result = ret;
    }

    // Creates a new asset
    function createAsset(string memory name, string memory domain, string memory precision) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "createAsset(string,string,string)",
            name,
            domain,
            precision);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit CreatedAsset(name, domain, precision);
        result = ret;
    }

    // Gets asset info
    function getAssetInfo(string memory name) public  returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAssetInfo(string)",
            name);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    // Adds asset to iroha account
    function addAssetQuantity(string memory asset, string memory amount) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "addAssetQuantity(string,string)",
            asset,
            amount);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit AddedAmount(asset, amount);
        result = ret;
    }

    // Subtracts asset to iroha account
    function subtractAssetQuantity(string memory asset, string memory amount) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "subtractAssetQuantity(string,string)",
            asset,
            amount);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit SubtractedAmount(asset, amount);
        result = ret;
    }

    //Queries balance of an iroha account
    function queryBalance(string memory _account, string memory _asset) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "getAssetBalance(string,string)",
            _account,
            _asset);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success,"Error calling service contract function ");
        result = ret;
    }

     // Sets the account detail
    function setAccountDetail(string memory name, string memory key, string memory value) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "setAccountDetail(string,string,string)",
            name,
            key,
            value);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        emit Updated(name, key, value);
        result = ret;
    }

    // Gets account details
    function getAccountDetail() public returns (bytes memory result) {
         bytes memory payload = abi.encodeWithSignature(
            "getAccountDetail()");
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");
        result = ret;
    }

    //Transfers asset from one iroha account to another
    function transferAsset(string memory src, string memory dst, string memory asset, string memory description, string memory amount) public returns (bytes memory result) {
        bytes memory payload = abi.encodeWithSignature(
            "transferAsset(string,string,string,string,string)",
            src,
            dst,
            asset,
            description,
            amount);
        (bool success, bytes memory ret) = address(serviceContractAddress).delegatecall(payload);
        require(success, "Error calling service contract function");

        emit Transferred(src, dst, amount);
        result = ret;
    }

    function createAndSetupAccount(string memory adminAccountId, string memory userAccountName, string memory userAccountId, string memory assetId, string memory domain, string memory description, string memory amount, string memory key, string memory value, string memory publicKey) public returns (bytes memory result) {
        result = createAccount(userAccountName, domain, publicKey);
        result = transferAsset(adminAccountId, userAccountId, assetId, description, amount);
        result = setAccountDetail(userAccountId, key, value);
    }

    function setsAsset(string memory assetName, string memory domainName, string memory precision, string memory assetId, string memory amount) public returns (bytes memory result) {
        result = createAsset(assetName, domainName, precision);
        result = addAssetQuantity(assetId, amount);
    }
}
