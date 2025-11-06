// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17; // <-- we’ll target 0.8.17 in the compiler below

contract FileRegistry {
    event FileAdded(bytes32 indexed fileId, address indexed owner, string cid);
    event AccessGranted(bytes32 indexed fileId, address indexed user);
    event AccessRevoked(bytes32 indexed fileId, address indexed user);

    mapping(bytes32 => address) public owners;
    mapping(bytes32 => string) private filenames;
    mapping(bytes32 => string) private cids;
    mapping(bytes32 => bytes32) private fileHashes;
    mapping(bytes32 => mapping(address => bool)) private allowed;
    mapping(bytes32 => bool) public exists;

    modifier onlyOwner(bytes32 fileId) {
        require(owners[fileId] == msg.sender, "Not owner");
        _;
    }

    function addFile(bytes32 fileId, string calldata filename, string calldata cid, bytes32 fileHash) external {
        require(!exists[fileId], "Already exists");
        owners[fileId] = msg.sender;
        filenames[fileId] = filename;
        cids[fileId] = cid;
        fileHashes[fileId] = fileHash;
        exists[fileId] = true;
        emit FileAdded(fileId, msg.sender, cid);
    }

    function grantAccess(bytes32 fileId, address user) external onlyOwner(fileId) {
        allowed[fileId][user] = true;
        emit AccessGranted(fileId, user);
    }

    function revokeAccess(bytes32 fileId, address user) external onlyOwner(fileId) {
        allowed[fileId][user] = false;
        emit AccessRevoked(fileId, user);
    }

    function canAccess(bytes32 fileId, address user) public view returns (bool) {
        return owners[fileId] == user || allowed[fileId][user];
    }

    function getFile(bytes32 fileId)
        external
        view
        returns (address owner, string memory filename, string memory cid, bytes32 fileHash)
    {
        require(exists[fileId], "No such file");
        require(canAccess(fileId, msg.sender), "Access denied");
        return (owners[fileId], filenames[fileId], cids[fileId], fileHashes[fileId]);
    }
}
