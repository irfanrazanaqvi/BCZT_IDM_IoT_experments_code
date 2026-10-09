// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IdentityRegistry.sol";

/// @title ZeroTrustAccess
/// @notice Evaluates every access request against the "never trust, always
/// verify" principle: identity status, request signature freshness (nonce),
/// device class/attribute policy, and an off-chain-computed but on-chain
/// verifiable trust score are all re-checked on each call. No session-based
/// implicit trust is cached on-chain.
contract ZeroTrustAccess {
    enum Effect { DENY, STEP_UP, ALLOW }

    struct Policy {
        uint16 minTrustBp;        // minimum trust score, basis points (0-10000)
        uint16 stepUpMarginBp;    // margin above minTrust that still triggers step-up auth
        uint32 maxIdleSeconds;    // re-auth required if idle longer than this
        bool exists;
    }

    IdentityRegistry public immutable registry;
    address public policyAdmin;
    address public trustOracle; // address authorized to sign trust-score attestations

    mapping(bytes32 => Policy) public policies;                 // resourceId => policy
    mapping(bytes32 => mapping(string => bool)) public classAllowed; // resourceId => class => allowed
    mapping(bytes32 => bool) public usedNonce;                  // keccak256(did, nonce) => used

    event PolicyDefined(bytes32 indexed resourceId, uint16 minTrustBp, uint32 maxIdleSeconds);
    event AccessDecision(bytes32 indexed did, bytes32 indexed resourceId, Effect effect, string reason, uint256 timestamp);

    error NotPolicyAdmin();
    error UnknownPolicy();

    modifier onlyPolicyAdmin() {
        if (msg.sender != policyAdmin) revert NotPolicyAdmin();
        _;
    }

    constructor(address registryAddress, address oracle) {
        registry = IdentityRegistry(registryAddress);
        policyAdmin = msg.sender;
        trustOracle = oracle;
    }

    function definePolicy(
        bytes32 resourceId,
        uint16 minTrustBp,
        uint16 stepUpMarginBp,
        uint32 maxIdleSeconds,
        string[] calldata allowedClasses
    ) external onlyPolicyAdmin {
        policies[resourceId] = Policy(minTrustBp, stepUpMarginBp, maxIdleSeconds, true);
        for (uint256 i = 0; i < allowedClasses.length; i++) {
            classAllowed[resourceId][allowedClasses[i]] = true;
        }
        emit PolicyDefined(resourceId, minTrustBp, maxIdleSeconds);
    }

    /// @notice Evaluate a single access request. `trustScoreBp` (0-10000) must
    /// be countersigned by `trustOracle` to prevent a compromised device from
    /// self-declaring a high trust score.
    function evaluateAccess(
        bytes32 did,
        bytes32 resourceId,
        string calldata deviceClass,
        uint16 trustScoreBp,
        bytes calldata oracleSignature,
        uint256 nonce
    ) external returns (Effect effect) {
        bytes32 nonceKey = keccak256(abi.encode(did, nonce));

        IdentityRegistry.Status status = registry.getStatus(did);
        Policy memory pol = policies[resourceId];

        if (status != IdentityRegistry.Status.ACTIVE) {
            return _decide(did, resourceId, Effect.DENY, "device_not_active");
        }
        if (!pol.exists) {
            return _decide(did, resourceId, Effect.DENY, "no_policy");
        }
        if (usedNonce[nonceKey]) {
            return _decide(did, resourceId, Effect.DENY, "replay_detected");
        }
        usedNonce[nonceKey] = true;

        if (!classAllowed[resourceId][deviceClass]) {
            return _decide(did, resourceId, Effect.DENY, "class_not_allowed");
        }

        bytes32 scoreHash = keccak256(abi.encode(did, resourceId, trustScoreBp, nonce));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", scoreHash));
        if (_recover(ethHash, oracleSignature) != trustOracle) {
            return _decide(did, resourceId, Effect.DENY, "bad_oracle_signature");
        }

        if (trustScoreBp < pol.minTrustBp) {
            return _decide(did, resourceId, Effect.DENY, "trust_below_threshold");
        } else if (trustScoreBp < pol.minTrustBp + pol.stepUpMarginBp) {
            return _decide(did, resourceId, Effect.STEP_UP, "borderline_trust");
        }

        return _decide(did, resourceId, Effect.ALLOW, "ok");
    }

    function _decide(bytes32 did, bytes32 resourceId, Effect effect, string memory reason) internal returns (Effect) {
        emit AccessDecision(did, resourceId, effect, reason, block.timestamp);
        return effect;
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
