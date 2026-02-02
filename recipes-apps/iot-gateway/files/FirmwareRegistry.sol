// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FirmwareRegistry {
    struct FirmwareDetails {
        string version;
        string deviceClass;
        string sha256;
        uint256 size;
        string artifact;
        string signature;  // Digital signature of the metadata
        string publicKey;  // Public key for verification
        uint256 releasedAt;
    }

    mapping(string => FirmwareDetails) public firmwareDetails;

    event FirmwareRegistered(string version, string sha256);

    function registerFirmware(
        string memory _version,
        string memory _deviceClass,
        string memory _sha256,
        uint256 _size,
        string memory _artifact,
        string memory _signature,
        string memory _publicKey,
        uint256 _releasedAt
    ) public {
        firmwareDetails[_version] = FirmwareDetails({
            version: _version,
            deviceClass: _deviceClass,
            sha256: _sha256,
            size: _size,
            artifact: _artifact,
            signature: _signature,
            publicKey: _publicKey,
            releasedAt: _releasedAt
        });
        emit FirmwareRegistered(_version, _sha256);
    }

    function getFirmwareDetails(string memory _version) public view returns (
        string memory version,
        string memory deviceClass,
        string memory sha256Hash,
        uint256 size,
        string memory artifact,
        string memory signature,
        string memory publicKey,
        uint256 releasedAt
    ) {
        FirmwareDetails memory details = firmwareDetails[_version];
        return (
            details.version,
            details.deviceClass,
            details.sha256,
            details.size,
            details.artifact,
            details.signature,
            details.publicKey,
            details.releasedAt
        );
    }
}