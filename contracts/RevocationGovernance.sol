// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IdentityRegistry.sol";

/// @title RevocationGovernance
/// @notice Decentralized, threshold-voting governance for device
/// revocation, complementing the single-registrar model in
/// IdentityRegistry. A permissioned group of N voters (e.g. one per
/// consortium member: manufacturer, site operator, security auditor)
/// must cast at least `quorum` APPROVE votes before a revocation
/// proposal is executed against the registry. This mitigates the risk
/// of a single compromised or malicious registrar unilaterally revoking
/// (denying service to) a legitimate device, at the cost of the extra
/// voting-round latency quantified in Section 5.6 of the paper.
contract RevocationGovernance {
    struct Proposal {
        bytes32 did;
        string reason;
        uint32 approveCount;
        uint32 denyCount;
        bool finalized;
        bool approved;
        mapping(address => bool) hasVoted;
    }

    IdentityRegistry public immutable registry;
    address[] public voters;
    mapping(address => bool) public isVoter;
    uint32 public quorum;

    mapping(bytes32 => Proposal) private proposals;

    event ProposalCreated(bytes32 indexed proposalId, bytes32 indexed did, string reason);
    event VoteCast(bytes32 indexed proposalId, address indexed voter, bool approve);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);

    error NotVoter();
    error AlreadyVoted();
    error AlreadyFinalized();
    error UnknownProposal();

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

    function propose(bytes32 did, string calldata reason) external onlyVoter returns (bytes32 proposalId) {
        proposalId = keccak256(abi.encode(did, reason, block.timestamp, msg.sender));
        Proposal storage p = proposals[proposalId];
        p.did = did;
        p.reason = reason;
        emit ProposalCreated(proposalId, did, reason);
    }

    function castVote(bytes32 proposalId, bool approve) external onlyVoter {
        Proposal storage p = proposals[proposalId];
        if (p.did == bytes32(0)) revert UnknownProposal();
        if (p.finalized) revert AlreadyFinalized();
        if (p.hasVoted[msg.sender]) revert AlreadyVoted();

        p.hasVoted[msg.sender] = true;
        if (approve) {
            p.approveCount += 1;
        } else {
            p.denyCount += 1;
        }
        emit VoteCast(proposalId, msg.sender, approve);

        if (p.approveCount >= quorum) {
            p.finalized = true;
            p.approved = true;
            registry.revokeDevice(p.did, p.reason);
            emit ProposalFinalized(proposalId, true);
        } else if (p.denyCount > voters.length - quorum) {
            // mathematically impossible to reach quorum any more
            p.finalized = true;
            p.approved = false;
            emit ProposalFinalized(proposalId, false);
        }
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
