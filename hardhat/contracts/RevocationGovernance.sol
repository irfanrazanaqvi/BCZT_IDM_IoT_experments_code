// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IdentityRegistry.sol";

/// @title RevocationGovernance
/// @notice Threshold-voting governance for the privilege-restoring and terminal registry actions:
/// revoke, reinstate and fleet recall. A permissioned group of N voters (for example the
/// manufacturer, the site operator and a security auditor) must cast at least `quorum` APPROVE
/// votes before the action executes. After IdentityRegistry.lockGovernance(address(this)) no
/// single party can revoke, recall or reinstate; a single registrar can still register and
/// suspend (a reversible quarantine), and only a quorum can undo a suspension.
contract RevocationGovernance {
    enum Action { REVOKE, REINSTATE, REVOKE_BATCH }

    struct Proposal {
        bytes32 target;      // did, or keccak256(abi.encode(dids)) for a batch
        string reason;
        Action action;
        uint32 approveCount;
        uint32 denyCount;
        bool finalized;
        bool approved;
        bool executed;       // batch proposals: set once executeBatch has run
        mapping(address => bool) hasVoted;
    }

    IdentityRegistry public immutable registry;
    address[] public voters;
    mapping(address => bool) public isVoter;
    uint32 public quorum;

    mapping(bytes32 => Proposal) private proposals;

    event ProposalCreated(bytes32 indexed proposalId, bytes32 indexed target, Action action, string reason);
    event VoteCast(bytes32 indexed proposalId, address indexed voter, bool approve);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);
    event BatchExecuted(bytes32 indexed proposalId, uint256 devices);

    error NotVoter();
    error AlreadyVoted();
    error AlreadyFinalized();
    error UnknownProposal();
    error ProposalExists();
    error NotApprovedBatch();
    error BatchMismatch();

    modifier onlyVoter() {
        if (!isVoter[msg.sender]) revert NotVoter();
        _;
    }

    constructor(address registryAddress, address[] memory initialVoters, uint32 quorumSize) {
        registry = IdentityRegistry(registryAddress);
        for (uint256 i = 0; i < initialVoters.length; i++) {
            voters.push(initialVoters[i]);
            isVoter[initialVoters[i]] = true;
        }
        quorum = quorumSize;
    }

    /// @notice Propose to revoke one device.
    function propose(bytes32 did, string calldata reason) external onlyVoter returns (bytes32) {
        return _create(did, reason, Action.REVOKE);
    }

    /// @notice Propose to reinstate a suspended device.
    function proposeReinstate(bytes32 did) external onlyVoter returns (bytes32) {
        return _create(did, "reinstate", Action.REINSTATE);
    }

    /// @notice Propose a fleet recall. Voters approve a hash of the DID list; the list itself is
    /// supplied to executeBatch afterwards, so the proposal cost does not grow with the fleet.
    function proposeBatch(bytes32 batchHash, string calldata reason) external onlyVoter returns (bytes32) {
        return _create(batchHash, reason, Action.REVOKE_BATCH);
    }

    function _create(bytes32 target, string memory reason, Action action) internal returns (bytes32 proposalId) {
        proposalId = keccak256(abi.encode(target, reason, action, block.timestamp, msg.sender));
        Proposal storage p = proposals[proposalId];
        if (p.target != bytes32(0)) revert ProposalExists();
        p.target = target;
        p.reason = reason;
        p.action = action;
        emit ProposalCreated(proposalId, target, action, reason);
    }

    function castVote(bytes32 proposalId, bool approve) external onlyVoter {
        Proposal storage p = proposals[proposalId];
        if (p.target == bytes32(0)) revert UnknownProposal();
        if (p.finalized) revert AlreadyFinalized();
        if (p.hasVoted[msg.sender]) revert AlreadyVoted();

        p.hasVoted[msg.sender] = true;
        if (approve) p.approveCount += 1; else p.denyCount += 1;
        emit VoteCast(proposalId, msg.sender, approve);

        if (p.approveCount >= quorum) {
            p.finalized = true;
            p.approved = true;
            if (p.action == Action.REVOKE) registry.revokeDevice(p.target, p.reason);
            else if (p.action == Action.REINSTATE) registry.reinstateDevice(p.target);
            emit ProposalFinalized(proposalId, true);
        } else if (p.denyCount > voters.length - quorum) {
            p.finalized = true;
            p.approved = false;
            emit ProposalFinalized(proposalId, false);
        }
    }

    /// @notice Execute an approved fleet recall. Anyone may call it, but only with the exact list
    /// whose hash the quorum approved, and only once.
    function executeBatch(bytes32 proposalId, bytes32[] calldata dids) external returns (uint256 done) {
        Proposal storage p = proposals[proposalId];
        if (!(p.approved && p.action == Action.REVOKE_BATCH) || p.executed) revert NotApprovedBatch();
        if (keccak256(abi.encode(dids)) != p.target) revert BatchMismatch();
        p.executed = true;
        done = registry.revokeBatch(dids, p.reason);
        emit BatchExecuted(proposalId, done);
    }

    function getProposalStatus(bytes32 proposalId)
        external
        view
        returns (uint32 approveCount, uint32 denyCount, bool finalized, bool approved)
    {
        Proposal storage p = proposals[proposalId];
        return (p.approveCount, p.denyCount, p.finalized, p.approved);
    }
}
