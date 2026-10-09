// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IdentityRegistry
/// @notice On-chain DID-style identity registry for IoT devices. Devices are
/// identified by a deterministic DID derived from their Ed25519/secp256k1
/// public key. Registration requires a valid signature over the device's
/// declared attributes, binding the on-chain record to proof of key
/// possession. Status transitions (ACTIVE -> SUSPENDED -> REVOKED) are
/// append-only and emitted as events for off-chain SIEM ingestion.
contract IdentityRegistry {
    enum Status { UNKNOWN, ACTIVE, SUSPENDED, REVOKED }

    struct DeviceRecord {
        bytes32 did;
        address owner;
        bytes32 pubKeyHash;
        bytes32 attributeHash;
        string deviceClass;
        Status status;
        uint256 registeredAt;
        uint256 lastSeen;
    }

    address public admin;
    mapping(bytes32 => DeviceRecord) public devices;      // did => record
    mapping(bytes32 => bool) public revokedPubKeyHash;    // pubKeyHash => revoked
    mapping(address => bool) public registrars;           // gateways allowed to register on behalf of devices

    event DeviceRegistered(bytes32 indexed did, address indexed owner, string deviceClass, uint256 timestamp);
    event DeviceRevoked(bytes32 indexed did, string reason, uint256 timestamp);
    event DeviceSuspended(bytes32 indexed did, uint256 timestamp);
    event DeviceReinstated(bytes32 indexed did, uint256 timestamp);
    event RegistrarUpdated(address indexed registrar, bool allowed);

    error NotAdmin();
    error NotRegistrar();
    error AlreadyRegistered();
    error UnknownDevice();
    error InvalidSignature();
    error KeyRevoked();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyRegistrar() {
        if (!registrars[msg.sender] && msg.sender != admin) revert NotRegistrar();
        _;
    }

    constructor() {
        admin = msg.sender;
        registrars[msg.sender] = true;
    }

    function setRegistrar(address registrar, bool allowed) external onlyAdmin {
        registrars[registrar] = allowed;
        emit RegistrarUpdated(registrar, allowed);
    }

    /// @notice Register a new IoT device identity.
    /// @param pubKeyHash keccak256 hash of the device's raw public key
    /// @param attributeHash keccak256 hash of canonicalized device attributes (firmware, vendor, etc.)
    /// @param deviceClass free-text device class used by ZeroTrustAccess policies (e.g. "sensor")
    /// @param signature secp256k1 signature by the device key over keccak256(abi.encode(pubKeyHash, attributeHash, deviceClass, msg.sender))
    function registerDevice(
        bytes32 pubKeyHash,
        bytes32 attributeHash,
        string calldata deviceClass,
        bytes calldata signature,
        address deviceSigner
    ) external onlyRegistrar returns (bytes32 did) {
        if (revokedPubKeyHash[pubKeyHash]) revert KeyRevoked();

        bytes32 messageHash = keccak256(abi.encode(pubKeyHash, attributeHash, deviceClass, msg.sender));
        bytes32 ethSignedHash = _toEthSignedMessageHash(messageHash);
        address rec = _recover(ethSignedHash, signature);
        if (rec == address(0) || rec != deviceSigner) revert InvalidSignature();

        did = keccak256(abi.encodePacked("did:iot:", pubKeyHash));
        if (devices[did].registeredAt != 0) revert AlreadyRegistered();

        devices[did] = DeviceRecord({
            did: did,
            owner: msg.sender,
            pubKeyHash: pubKeyHash,
            attributeHash: attributeHash,
            deviceClass: deviceClass,
            status: Status.ACTIVE,
            registeredAt: block.timestamp,
            lastSeen: block.timestamp
        });

        emit DeviceRegistered(did, msg.sender, deviceClass, block.timestamp);
    }

    function revokeDevice(bytes32 did, string calldata reason) external onlyRegistrar {
        DeviceRecord storage rec = devices[did];
        if (rec.registeredAt == 0) revert UnknownDevice();
        rec.status = Status.REVOKED;
        revokedPubKeyHash[rec.pubKeyHash] = true;
        emit DeviceRevoked(did, reason, block.timestamp);
    }

    /// @notice Firmware-recall path: revoke many devices in one transaction.
    /// Unknown DIDs are skipped (not reverted) so one stale entry cannot block a recall.
    function revokeBatch(bytes32[] calldata dids, string calldata reason) external onlyRegistrar returns (uint256 done) {
        for (uint256 i = 0; i < dids.length; i++) {
            DeviceRecord storage rec = devices[dids[i]];
            if (rec.registeredAt == 0 || rec.status == Status.REVOKED) continue;
            rec.status = Status.REVOKED;
            revokedPubKeyHash[rec.pubKeyHash] = true;
            emit DeviceRevoked(dids[i], reason, block.timestamp);
            done++;
        }
    }

    /// @notice Quarantine many devices (reversible), e.g. while a vendor advisory is assessed.
    function suspendBatch(bytes32[] calldata dids) external onlyRegistrar returns (uint256 done) {
        for (uint256 i = 0; i < dids.length; i++) {
            DeviceRecord storage rec = devices[dids[i]];
            if (rec.status != Status.ACTIVE) continue;
            rec.status = Status.SUSPENDED;
            emit DeviceSuspended(dids[i], block.timestamp);
            done++;
        }
    }

    function suspendDevice(bytes32 did) external onlyRegistrar {
        DeviceRecord storage rec = devices[did];
        if (rec.registeredAt == 0) revert UnknownDevice();
        rec.status = Status.SUSPENDED;
        emit DeviceSuspended(did, block.timestamp);
    }

    function reinstateDevice(bytes32 did) external onlyRegistrar {
        DeviceRecord storage rec = devices[did];
        if (rec.registeredAt == 0) revert UnknownDevice();
        require(rec.status == Status.SUSPENDED, "only suspended devices can be reinstated");
        rec.status = Status.ACTIVE;
        emit DeviceReinstated(did, block.timestamp);
    }

    function touch(bytes32 did) external onlyRegistrar {
        if (devices[did].registeredAt == 0) revert UnknownDevice();
        devices[did].lastSeen = block.timestamp;
    }

    function getStatus(bytes32 did) external view returns (Status) {
        if (devices[did].registeredAt == 0) return Status.UNKNOWN;
        return devices[did].status;
    }

    function getRecord(bytes32 did) external view returns (DeviceRecord memory) {
        return devices[did];
    }

    // ---------------- signature helpers (ECDSA, no external libs) ----------------

    function _toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recover(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }
}
