//! Group Governance with Quorum Voting (§8.10)
//!
//! # What is this module?
//!
//! Implements the governance system for administrative decisions in groups.
//! Instead of a single admin having unilateral power over all actions,
//! the spec requires a quorum-based voting system where members vote
//! on proposals that affect the group's structure and policies.
//!
//! # Governance Model (§8.10.1)
//!
//! The spec defines three tiers of governance:
//!
//! 1. **Admin actions (unilateral):** Add members, remove non-admins,
//!    rename group, pin messages, trigger rekeying.
//!
//! 2. **Quorum-required actions:** Removing an admin always requires
//!    a supermajority quorum (67%). No exceptions, even with admin present.
//!
//! 3. **Degraded-mode actions:** When no admin is present, a standard
//!    quorum (51%) of non-admin members can perform all administrative
//!    actions, including promoting a new admin.
//!
//! # Vote Integrity
//!
//! Every vote is signed with Ed25519 using the `DOMAIN_GROUP_GOVERNANCE`
//! domain separator (§8.10.2). This prevents vote forgery and ensures
//! non-repudiation — a member cannot deny having cast a vote.
//!
//! # Quorum Rules (§8.10.2)
//!
//! - Default quorum: 51% of eligible voters must participate
//! - Default approval threshold: 67% of votes must approve
//! - Default voting period: 72 hours
//! - Votes are signed with Ed25519 to prevent forgery

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::ring_sig::{ring_sign, ring_verify, RingSignature};
use crate::crypto::signing::{sign, verify, DOMAIN_GROUP_GOVERNANCE};
use crate::error::MeshError;
use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default quorum fraction: 50% of eligible voters must participate.
/// Below this threshold, the proposal cannot be decided (stays Open).
// DEFAULT_QUORUM — protocol constant.
// Defined by the spec §8.10.2; must not change without a version bump.
pub const DEFAULT_QUORUM: f64 = 0.5;

/// Default approval threshold: 67% of cast votes must approve.
/// This is the supermajority threshold from §8.10.2 for high-risk actions.
// DEFAULT_APPROVAL_THRESHOLD — protocol constant.
// Defined by the spec §8.10.2; must not change without a version bump.
pub const DEFAULT_APPROVAL_THRESHOLD: f64 = 0.67;

/// Default voting period: 72 hours (259200 seconds).
/// Proposals that are not decided within this window expire and become Rejected.
// DEFAULT_VOTING_PERIOD_SECS — protocol constant.
// Chosen to give members across time zones ample time to vote.
pub const DEFAULT_VOTING_PERIOD_SECS: u64 = 72 * 3600;

// ---------------------------------------------------------------------------
// Group Role
// ---------------------------------------------------------------------------

/// A member's role in the governance system.
///
/// Roles determine who can create proposals and who can vote.
/// The hierarchy is: Admin > Moderator > Member. Each role has
/// different governance weights and proposal creation permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRole {
    /// Full administrator. Can propose RemoveMember and Dissolve actions.
    /// Holds the group's private key and can perform unilateral actions.
    Admin,

    /// Moderator. Can propose ChangeRole and ChangeSettings actions.
    /// Cannot propose member removal or group dissolution.
    Moderator,

    /// Regular member. Cannot create proposals but can vote on them.
    /// This is the default role assigned to new group members.
    Member,
}

// ---------------------------------------------------------------------------
// Governance Action
// ---------------------------------------------------------------------------

/// Actions that require governance approval via quorum voting.
///
/// Each variant represents a specific administrative change that
/// cannot be performed unilaterally. The action is embedded in a
/// Proposal and voted on by eligible members.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAction {
    /// Remove a member from the group. Triggers the superset ring
    /// model (§8.7.4) and Sender Key rekeying after approval.
    /// Only admins can propose this action.
    RemoveMember {
        /// The peer ID of the member to remove.
        peer_id: PeerId,
    },

    /// Change a member's role within the group.
    /// Admins and moderators can propose role changes.
    /// Promoting to admin requires quorum confirmation (§8.10.1).
    ChangeRole {
        /// The peer ID of the member whose role will change.
        peer_id: PeerId,
        /// The new role to assign to the member.
        new_role: GroupRole,
    },

    /// Change the group's governance policy (quorum threshold,
    /// approval threshold, voting period, or eligible roles).
    /// Only admins can propose policy changes to prevent
    /// moderators from weakening governance controls.
    ChangePolicy {
        /// The new governance policy to apply.
        new_policy: GovernancePolicy,
    },

    /// Change group settings such as name, description, or avatar.
    /// The settings payload is a JSON string to keep the governance
    /// module decoupled from the settings schema.
    /// Admins and moderators can propose settings changes.
    ChangeSettings {
        /// JSON-encoded settings changes.
        settings_json: String,
    },

    /// Dissolve the group entirely. This is irreversible — all
    /// members are removed and the group keypair is destroyed.
    /// Only admins can propose dissolution.
    Dissolve,
}

// ---------------------------------------------------------------------------
// Vote Decision
// ---------------------------------------------------------------------------

/// The decision a voter casts on a proposal.
///
/// Binary choice: approve or reject. Abstention is implicit —
/// members who do not vote within the voting period are counted
/// as non-participants for quorum purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDecision {
    /// The voter approves the proposed action.
    Approve,

    /// The voter rejects the proposed action.
    Reject,
}

// VoteDecision needs a byte representation for signature construction.
// This ensures deterministic encoding across platforms.
impl VoteDecision {
    /// Returns a single-byte encoding of the decision for signatures.
    /// Approve = 0x01, Reject = 0x00.
    fn as_byte(&self) -> u8 {
        // Deterministic encoding: approve is 1, reject is 0.
        // This byte is included in the Ed25519 signature payload.
        match self {
            // Approve maps to 0x01 — the "positive" vote.
            VoteDecision::Approve => 0x01,
            // Reject maps to 0x00 — the "negative" vote.
            VoteDecision::Reject => 0x00,
        }
    }
}

// ---------------------------------------------------------------------------
// Proposal Status
// ---------------------------------------------------------------------------

/// The lifecycle status of a governance proposal.
///
/// Proposals transition through these states:
/// Open → Approved (if quorum + threshold met)
/// Open → Rejected (if approval mathematically impossible, or expired)
/// Open → Expired (if voting period elapses without a decision)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// The proposal is still accepting votes.
    /// Transitions to Approved, Rejected, or Expired.
    Open,

    /// The proposal has been approved by quorum.
    /// The proposed action should now be executed.
    Approved,

    /// The proposal was rejected — either enough reject votes were
    /// cast to make approval mathematically impossible, or the
    /// proposal expired without reaching quorum.
    Rejected,

    /// The proposal's voting period has elapsed without a decision.
    /// Functionally equivalent to Rejected — the action is not taken.
    Expired,
}

// ---------------------------------------------------------------------------
// Vote
// ---------------------------------------------------------------------------

/// A signed vote on a governance proposal.
///
/// Each vote includes an Ed25519 signature over (proposal_id || decision)
/// using the DOMAIN_GROUP_GOVERNANCE domain separator. This prevents
/// vote forgery and ensures non-repudiation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// The voter's decision: approve or reject the proposal.
    pub decision: VoteDecision,

    /// Cryptographic proof that an eligible voter cast this vote.
    pub proof: GovernanceProof,
}

/// Proof attached to a governance proposal or vote.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GovernanceProof {
    /// Attributable Ed25519 proof used for Open and Public groups.
    Attributed {
        /// Peer ID of the acting member.
        signer: PeerId,
        /// Actual Ed25519 public key used for verification.
        ed25519_public: [u8; 32],
        /// Ed25519 signature over the governance payload.
        signature: Vec<u8>,
    },
    /// Unlinkable ring proof used for Private and Closed groups.
    Ring {
        /// AOS ring signature over the current member public-key set.
        ring_signature: RingSignature,
    },
}

// ---------------------------------------------------------------------------
// Governance Policy
// ---------------------------------------------------------------------------

/// The governance policy that controls how proposals are decided.
///
/// Each group has its own policy that can be changed via a
/// ChangePolicy proposal (which itself must pass under the
/// current policy — preventing governance bypass).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernancePolicy {
    /// Minimum fraction of eligible voters that must vote (0.0–1.0).
    /// If fewer than `quorum * eligible_voter_count` votes are cast,
    /// the proposal remains Open until the voting period expires.
    pub quorum: f64,

    /// Fraction of yes-votes needed to approve (0.0–1.0).
    /// Calculated as: approve_count / total_votes_cast >= approval_threshold.
    /// Default is 0.67 (two-thirds supermajority).
    pub approval_threshold: f64,

    /// How long proposals stay open for voting (seconds).
    /// After this period, unresolved proposals transition to Expired.
    pub voting_period_secs: u64,

    /// Which roles are allowed to create proposals.
    /// Empty means no one can create proposals (effectively frozen governance).
    pub proposer_roles: Vec<GroupRole>,

    /// Which roles are allowed to vote on proposals.
    /// Typically all members can vote, but this can be restricted.
    pub voter_roles: Vec<GroupRole>,
}

// PartialEq impl for GovernancePolicy — compares all fields.
// f64 fields use bitwise equality via to_bits() to avoid NaN issues.
impl PartialEq for GovernancePolicy {
    fn eq(&self, other: &Self) -> bool {
        // Compare f64 fields using to_bits() for exact bitwise equality.
        // This avoids NaN != NaN surprises from IEEE 754.
        self.quorum.to_bits() == other.quorum.to_bits()
            && self.approval_threshold.to_bits() == other.approval_threshold.to_bits()
            && self.voting_period_secs == other.voting_period_secs
            && self.proposer_roles == other.proposer_roles
            && self.voter_roles == other.voter_roles
    }
}

// Eq is safe because we handle NaN via to_bits() in PartialEq.
impl Eq for GovernancePolicy {}

// GovernancePolicy implementation — construction and validation.
impl GovernancePolicy {
    /// Creates the default governance policy per §8.10.2.
    ///
    /// - Quorum: 50% of eligible voters
    /// - Approval threshold: 67% (supermajority)
    /// - Voting period: 72 hours
    /// - Proposer roles: Admin and Moderator
    /// - Voter roles: Admin, Moderator, and Member (all members vote)
    pub fn default_policy() -> Self {
        // Construct policy with spec-defined defaults.
        // These values come directly from §8.10.2.
        Self {
            quorum: DEFAULT_QUORUM,
            approval_threshold: DEFAULT_APPROVAL_THRESHOLD,
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            // Admins and moderators can propose by default.
            // Members must escalate through a moderator or admin.
            proposer_roles: vec![GroupRole::Admin, GroupRole::Moderator],
            // All roles can vote — this is the democratic baseline.
            // Restricting voter_roles is possible but not default.
            voter_roles: vec![GroupRole::Admin, GroupRole::Moderator, GroupRole::Member],
        }
    }

    /// Validates that the policy parameters are within acceptable bounds.
    ///
    /// Returns an error if any parameter is out of range:
    /// - quorum must be in (0.0, 1.0]
    /// - approval_threshold must be in (0.0, 1.0]
    /// - voting_period_secs must be > 0
    /// - proposer_roles must not be empty
    /// - voter_roles must not be empty
    pub fn validate(&self) -> Result<(), MeshError> {
        // Quorum must be positive and at most 1.0 (100%).
        // A zero quorum would allow proposals with no votes.
        if self.quorum <= 0.0 || self.quorum > 1.0 {
            return Err(MeshError::OutOfRange {
                field: "quorum",
                value: format!("{}", self.quorum),
            });
        }

        // Approval threshold must be positive and at most 1.0 (100%).
        // A zero threshold would approve any proposal with at least one vote.
        if self.approval_threshold <= 0.0 || self.approval_threshold > 1.0 {
            return Err(MeshError::OutOfRange {
                field: "approval_threshold",
                value: format!("{}", self.approval_threshold),
            });
        }

        // Voting period must be non-zero to give members time to vote.
        // A zero period would immediately expire all proposals.
        if self.voting_period_secs == 0 {
            return Err(MeshError::OutOfRange {
                field: "voting_period_secs",
                value: "0".to_string(),
            });
        }

        // At least one role must be able to create proposals.
        // Empty proposer_roles effectively freezes governance.
        if self.proposer_roles.is_empty() {
            return Err(MeshError::Internal(
                "proposer_roles must not be empty".to_string(),
            ));
        }

        // At least one role must be able to vote.
        // Empty voter_roles would prevent any proposal from passing.
        if self.voter_roles.is_empty() {
            return Err(MeshError::Internal(
                "voter_roles must not be empty".to_string(),
            ));
        }

        // All checks passed — the policy is valid.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Proposal
// ---------------------------------------------------------------------------

/// A proposal for a group administrative action.
///
/// Proposals are the central governance primitive. A member creates a
/// proposal, other members vote on it, and the system tallies votes
/// to determine whether the action should be executed. The proposal
/// tracks all votes and the current status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique ID for this proposal (random 16 bytes).
    /// Generated at creation time using the system RNG.
    pub id: [u8; 16],

    /// The group this proposal belongs to.
    /// Used to scope the proposal and prevent cross-group replay.
    pub group_id: [u8; 16],

    /// Who created the proposal when attribution is intentionally visible.
    /// Private and Closed groups omit this from the outer proposal surface.
    pub proposer: Option<PeerId>,

    /// Proof that an eligible member created the proposal.
    pub proposer_proof: GovernanceProof,

    /// What action is proposed (remove member, change role, etc.).
    /// The action is immutable after creation — you cannot change
    /// what a proposal does after people have started voting on it.
    pub action: GovernanceAction,

    /// When the proposal was created (Unix timestamp seconds).
    /// Used together with `expires_at` to determine the voting window.
    pub created_at: u64,

    /// When the proposal expires (Unix timestamp seconds).
    /// Computed as `created_at + policy.voting_period_secs` at creation.
    pub expires_at: u64,

    /// Votes cast so far, in chronological order.
    /// Each voter can cast at most one vote — duplicates are rejected.
    pub votes: Vec<Vote>,

    /// Current lifecycle status of the proposal.
    /// Transitions: Open → Approved | Rejected | Expired.
    pub status: ProposalStatus,
}

// ---------------------------------------------------------------------------
// Proposal Creation
// ---------------------------------------------------------------------------

/// Create a new proposal for a governance action.
///
/// Validates that the proposer has the required role for the action type:
/// - RemoveMember and Dissolve: Admin only
/// - ChangeRole and ChangeSettings: Admin or Moderator
/// - ChangePolicy: Admin only (prevents moderators from weakening governance)
///
/// Returns the new proposal with status Open and an empty vote list.
/// The proposal ID is generated randomly using the system RNG.
pub fn create_proposal(
    group_id: &[u8; 16],
    proposer: &PeerId,
    proposer_role: &GroupRole,
    action: GovernanceAction,
    policy: &GovernancePolicy,
    secret_key: &[u8; 32],
) -> Result<Proposal, MeshError> {
    // Validate the policy before using it for proposal creation.
    // This catches misconfigured policies early.
    policy.validate()?;

    // Check that the proposer's role is in the policy's proposer_roles list.
    // This enforces role-based access control on proposal creation.
    if !policy.proposer_roles.contains(proposer_role) {
        return Err(MeshError::Internal(format!(
            "role {:?} is not allowed to create proposals",
            proposer_role,
        )));
    }

    // Enforce action-specific role restrictions per §8.10.1.
    // Some actions require higher-privilege roles regardless of the policy.
    validate_action_role(&action, proposer_role)?;

    // Get the current Unix timestamp for the creation time.
    // The expiry is computed from this timestamp plus the voting period.
    let now = current_unix_timestamp();

    // Compute the expiry time by adding the voting period to now.
    // Overflow is handled with saturating_add to prevent wrap-around.
    let expires_at = now.saturating_add(policy.voting_period_secs);

    // Generate a random 16-byte proposal ID using the system RNG.
    // This ensures uniqueness across all proposals in the group.
    let mut id = [0u8; 16];
    getrandom::fill(&mut id)
        .map_err(|e| MeshError::Internal(format!("RNG failed for proposal ID: {}", e)))?;

    // Construct the proposal with Open status and empty vote list.
    // The caller is responsible for distributing this to group members.
    let proof = governance_attributed_proof(
        secret_key,
        proposer,
        proposal_message(&id, group_id, &action, now, expires_at)?,
    );

    Ok(Proposal {
        id,
        group_id: *group_id,
        proposer: Some(*proposer),
        proposer_proof: proof,
        action,
        created_at: now,
        expires_at,
        votes: Vec::new(),
        status: ProposalStatus::Open,
    })
}

/// Create a proposal with an unlinkable ring proof for Private/Closed groups.
pub fn create_ring_proposal(
    group_id: &[u8; 16],
    proposer_role: &GroupRole,
    action: GovernanceAction,
    policy: &GovernancePolicy,
    secret_key: &[u8; 32],
    ring: &[[u8; 32]],
) -> Result<Proposal, MeshError> {
    policy.validate()?;
    if !policy.proposer_roles.contains(proposer_role) {
        return Err(MeshError::Internal(format!(
            "role {:?} is not allowed to create proposals",
            proposer_role,
        )));
    }
    validate_action_role(&action, proposer_role)?;

    let now = current_unix_timestamp();
    let expires_at = now.saturating_add(policy.voting_period_secs);
    let mut id = [0u8; 16];
    getrandom::fill(&mut id)
        .map_err(|e| MeshError::Internal(format!("RNG failed for proposal ID: {}", e)))?;
    let message = proposal_message(&id, group_id, &action, now, expires_at)?;
    let ring_signature = ring_sign(secret_key, ring, &message)
        .map_err(|e| MeshError::Internal(format!("ring proposal signing failed: {e}")))?;

    Ok(Proposal {
        id,
        group_id: *group_id,
        proposer: None,
        proposer_proof: GovernanceProof::Ring { ring_signature },
        action,
        created_at: now,
        expires_at,
        votes: Vec::new(),
        status: ProposalStatus::Open,
    })
}

/// Validates that the proposer's role is sufficient for the given action.
///
/// Per §8.10.1:
/// - RemoveMember: Admin only (removing a member is a high-risk action)
/// - Dissolve: Admin only (irreversible group destruction)
/// - ChangePolicy: Admin only (prevents moderators from weakening governance)
/// - ChangeRole: Admin or Moderator
/// - ChangeSettings: Admin or Moderator
fn validate_action_role(
    action: &GovernanceAction,
    proposer_role: &GroupRole,
) -> Result<(), MeshError> {
    // Determine which roles are allowed for this specific action.
    // This is separate from the policy's proposer_roles — it's a hard
    // constraint that cannot be overridden by policy changes.
    match action {
        // RemoveMember requires Admin — non-admins cannot propose removal.
        // This prevents moderators from weaponizing the governance system.
        GovernanceAction::RemoveMember { .. } => {
            if *proposer_role != GroupRole::Admin {
                return Err(MeshError::Internal(
                    "only admins can propose member removal".to_string(),
                ));
            }
        }

        // Dissolve requires Admin — group destruction is irreversible.
        // Even with quorum approval, only an admin can initiate dissolution.
        GovernanceAction::Dissolve => {
            if *proposer_role != GroupRole::Admin {
                return Err(MeshError::Internal(
                    "only admins can propose group dissolution".to_string(),
                ));
            }
        }

        // ChangePolicy requires Admin — prevents moderators from
        // lowering thresholds to gain effective admin power.
        GovernanceAction::ChangePolicy { .. } => {
            if *proposer_role != GroupRole::Admin {
                return Err(MeshError::Internal(
                    "only admins can propose policy changes".to_string(),
                ));
            }
        }

        // ChangeRole allows Admin or Moderator — moderators can propose
        // role changes for members below them in the hierarchy.
        GovernanceAction::ChangeRole { .. } => {
            if *proposer_role == GroupRole::Member {
                return Err(MeshError::Internal(
                    "members cannot propose role changes".to_string(),
                ));
            }
        }

        // ChangeSettings allows Admin or Moderator — settings changes
        // are lower-risk than structural changes.
        GovernanceAction::ChangeSettings { .. } => {
            if *proposer_role == GroupRole::Member {
                return Err(MeshError::Internal(
                    "members cannot propose settings changes".to_string(),
                ));
            }
        }
    }

    // The role is sufficient for this action type.
    Ok(())
}

// ---------------------------------------------------------------------------
// Voting
// ---------------------------------------------------------------------------

/// Cast a vote on a governance proposal.
///
/// The vote is signed with Ed25519 using `DOMAIN_GROUP_GOVERNANCE` over
/// the payload `(proposal_id || decision_byte)`. This binds the vote
/// to a specific proposal and decision, preventing:
/// - Vote forgery (only the key holder can sign)
/// - Vote replay across proposals (proposal ID is in the signed data)
/// - Decision tampering (decision byte is in the signed data)
///
/// Validates:
/// - The proposal is still Open
/// - The voter has not already voted on this proposal
/// - The voter's role is in the policy's voter_roles
///
/// After casting the vote, automatically calls `tally_votes` to check
/// if the proposal has reached a decision.
pub fn cast_vote(
    proposal: &mut Proposal,
    voter: &PeerId,
    voter_role: &GroupRole,
    decision: VoteDecision,
    secret_key: &[u8; 32],
    policy: &GovernancePolicy,
    eligible_voter_count: usize,
) -> Result<(), MeshError> {
    // Only accept votes on proposals that are still Open.
    // Approved, Rejected, and Expired proposals are immutable.
    if proposal.status != ProposalStatus::Open {
        return Err(MeshError::Internal(format!(
            "proposal is {:?}, not Open — cannot accept votes",
            proposal.status,
        )));
    }

    // Check that the voter's role is in the policy's voter_roles.
    // This enforces role-based access control on voting.
    if !policy.voter_roles.contains(voter_role) {
        return Err(MeshError::Internal(format!(
            "role {:?} is not allowed to vote",
            voter_role,
        )));
    }

    // Reject duplicate votes — each voter can cast exactly one vote.
    // Changing your vote is not supported; you must live with your choice.
    if proposal.votes.iter().any(|v| {
        matches!(
            &v.proof,
            GovernanceProof::Attributed { signer, .. } if *signer == *voter
        )
    }) {
        return Err(MeshError::Internal(
            "voter has already cast a vote on this proposal".to_string(),
        ));
    }

    // Build the signature payload: proposal_id (16 bytes) || decision (1 byte).
    // This binds the signature to this specific proposal and decision.
    let mut sig_payload = Vec::with_capacity(17);
    // The proposal ID ensures the vote cannot be replayed on another proposal.
    sig_payload.extend_from_slice(&proposal.id);
    // The decision byte ensures the voter's intent cannot be altered.
    sig_payload.push(decision.as_byte());

    // Sign the payload with the voter's Ed25519 secret key.
    // Uses DOMAIN_GROUP_GOVERNANCE for cross-protocol replay prevention.
    let proof = governance_attributed_proof(secret_key, voter, sig_payload);

    // Construct and record the vote with the cryptographic signature.
    let vote = Vote { decision, proof };

    // Append the vote to the proposal's vote list.
    // Votes are stored in chronological order.
    proposal.votes.push(vote);

    // After recording the vote, check if the proposal has reached
    // a decision (approved or rejected). This provides immediate
    // feedback rather than requiring a separate tally step.
    tally_votes(proposal, policy, eligible_voter_count);

    // Vote successfully recorded and tallied.
    Ok(())
}

/// Cast a governance vote using an unlinkable ring proof.
pub fn cast_ring_vote(
    proposal: &mut Proposal,
    voter_role: &GroupRole,
    decision: VoteDecision,
    secret_key: &[u8; 32],
    ring: &[[u8; 32]],
    policy: &GovernancePolicy,
    eligible_voter_count: usize,
) -> Result<(), MeshError> {
    if proposal.status != ProposalStatus::Open {
        return Err(MeshError::Internal(format!(
            "proposal is {:?}, not Open — cannot accept votes",
            proposal.status,
        )));
    }
    if !policy.voter_roles.contains(voter_role) {
        return Err(MeshError::Internal(format!(
            "role {:?} is not allowed to vote",
            voter_role,
        )));
    }

    let mut sig_payload = Vec::with_capacity(17);
    sig_payload.extend_from_slice(&proposal.id);
    sig_payload.push(decision.as_byte());
    let ring_signature = ring_sign(secret_key, ring, &sig_payload)
        .map_err(|e| MeshError::Internal(format!("ring vote signing failed: {e}")))?;

    proposal.votes.push(Vote {
        decision,
        proof: GovernanceProof::Ring { ring_signature },
    });
    tally_votes_with_ring(proposal, policy, eligible_voter_count, Some(ring));
    Ok(())
}

/// Verify that a vote's Ed25519 signature is valid.
///
/// Reconstructs the signed payload (proposal_id || decision_byte) and
/// verifies the signature against the voter's public key (which is
/// their peer ID, since PeerId wraps a 32-byte Ed25519 public key).
///
/// Returns true if the signature is valid, false otherwise.
pub fn verify_vote_signature(proposal_id: &[u8; 16], vote: &Vote) -> bool {
    verify_vote_signature_with_ring(proposal_id, vote, None)
}

/// Verify a vote proof, optionally permitting ring proofs against the supplied ring.
pub fn verify_vote_signature_with_ring(
    proposal_id: &[u8; 16],
    vote: &Vote,
    ring: Option<&[[u8; 32]]>,
) -> bool {
    // Reconstruct the exact payload that was signed.
    // Must match the construction in cast_vote exactly.
    let mut sig_payload = Vec::with_capacity(17);
    // Append the proposal ID (16 bytes).
    sig_payload.extend_from_slice(proposal_id);
    // Append the decision byte (1 byte).
    sig_payload.push(vote.decision.as_byte());

    match &vote.proof {
        GovernanceProof::Attributed {
            signer,
            ed25519_public,
            signature,
        } => {
            if PeerId::from_ed25519_pub(ed25519_public) != *signer {
                return false;
            }
            verify(
                ed25519_public,
                DOMAIN_GROUP_GOVERNANCE,
                &sig_payload,
                signature,
            )
        }
        GovernanceProof::Ring { ring_signature } => ring
            .map(|public_ring| ring_verify(public_ring, &sig_payload, ring_signature))
            .unwrap_or(false),
    }
}

// ---------------------------------------------------------------------------
// Tallying
// ---------------------------------------------------------------------------

/// Tally votes and determine the proposal outcome.
///
/// This function implements the quorum + threshold decision logic:
///
/// 1. **Quorum check:** Have enough eligible voters participated?
///    Required: `votes_cast >= ceil(quorum * eligible_voter_count)`
///
/// 2. **Approval check:** Of the votes cast, do enough approve?
///    Required: `approve_count >= ceil(approval_threshold * votes_cast)`
///
/// 3. **Early rejection:** Is approval mathematically impossible?
///    If `max_possible_approvals < required_approvals`, reject early.
///    `max_possible_approvals = current_approvals + remaining_votes`
///
/// The proposal status is updated in place and also returned.
pub fn tally_votes(
    proposal: &mut Proposal,
    policy: &GovernancePolicy,
    eligible_voter_count: usize,
) -> ProposalStatus {
    tally_votes_with_ring(proposal, policy, eligible_voter_count, None)
}

/// Tally votes, verifying attributable or ring proofs as appropriate.
pub fn tally_votes_with_ring(
    proposal: &mut Proposal,
    policy: &GovernancePolicy,
    eligible_voter_count: usize,
    ring: Option<&[[u8; 32]]>,
) -> ProposalStatus {
    // Only tally proposals that are still Open.
    // Decided proposals should not have their status changed.
    if proposal.status != ProposalStatus::Open {
        return proposal.status;
    }

    // Verify every vote's Ed25519 signature before counting.
    // A vote with an invalid signature is treated as if it does not exist —
    // it is excluded from both quorum and threshold calculations. This
    // prevents an attacker who has compromised the proposal storage (but
    // not the voters' keys) from injecting forged votes to sway outcomes.
    //
    // Note: we do NOT remove invalid votes from the Vec here because
    // tally_votes takes `&mut Proposal` only for status updates, and
    // mutating the vote list during iteration would require a separate
    // pass. Instead, we count only verified votes below.
    let verified_approve_count = proposal
        .votes
        .iter()
        .filter(|v| verify_vote_signature_with_ring(&proposal.id, v, ring))
        .filter(|v| v.decision == VoteDecision::Approve)
        .count();

    // Count total verified votes (regardless of decision).
    let verified_total = proposal
        .votes
        .iter()
        .filter(|v| verify_vote_signature_with_ring(&proposal.id, v, ring))
        .count();

    // Use the verified counts for all subsequent calculations.
    // Votes with invalid signatures are silently excluded.
    let approve_count = verified_approve_count;

    // Reject count is total verified votes minus verified approvals.
    let total_votes = verified_total;
    let reject_count = total_votes - approve_count;

    // Calculate the minimum number of votes needed for quorum.
    // Use ceiling to ensure we never round down (e.g., 51% of 3 = 2, not 1).
    let quorum_needed = ceiling_fraction(policy.quorum, eligible_voter_count);

    // Check if approval is mathematically impossible.
    // If all remaining eligible voters approved, could we still reach threshold?
    let remaining_votes = eligible_voter_count.saturating_sub(total_votes);
    // Maximum possible approvals = current approvals + all remaining votes.
    let max_possible_approvals = approve_count + remaining_votes;

    // Calculate how many approvals would be needed if all eligible voted.
    // We need `approve_count >= ceil(threshold * total_cast)` where
    // total_cast could be up to eligible_voter_count.
    let approvals_needed_at_full =
        ceiling_fraction(policy.approval_threshold, eligible_voter_count);

    // Early rejection: if even with all remaining voters approving,
    // we still cannot reach the threshold, reject immediately.
    if max_possible_approvals < approvals_needed_at_full {
        proposal.status = ProposalStatus::Rejected;
        return ProposalStatus::Rejected;
    }

    // Also reject if enough explicit rejections have been cast.
    // If reject_count exceeds the complement of the threshold applied
    // to eligible_voter_count, approval is impossible.
    let max_rejections_allowed = eligible_voter_count - approvals_needed_at_full;
    if reject_count > max_rejections_allowed {
        proposal.status = ProposalStatus::Rejected;
        return ProposalStatus::Rejected;
    }

    // Quorum check: have enough voters participated?
    // If not, the proposal stays Open until more votes arrive or it expires.
    if total_votes < quorum_needed {
        return ProposalStatus::Open;
    }

    // Quorum is met. Now check the approval threshold against actual votes.
    // We need: approve_count >= ceil(approval_threshold * total_votes)
    let approvals_needed = ceiling_fraction(policy.approval_threshold, total_votes);

    // If enough approvals have been cast, the proposal is approved.
    if approve_count >= approvals_needed {
        proposal.status = ProposalStatus::Approved;
        return ProposalStatus::Approved;
    }

    // Quorum met but threshold not yet reached — stays Open.
    // More votes could still push it over the threshold.
    ProposalStatus::Open
}

/// Verify a proposal proof, optionally allowing an unlinkable ring proof.
pub fn verify_proposal_signature(proposal: &Proposal, ring: Option<&[[u8; 32]]>) -> bool {
    let Ok(message) = proposal_message(
        &proposal.id,
        &proposal.group_id,
        &proposal.action,
        proposal.created_at,
        proposal.expires_at,
    ) else {
        return false;
    };
    match &proposal.proposer_proof {
        GovernanceProof::Attributed {
            signer,
            ed25519_public,
            signature,
        } => {
            if proposal.proposer != Some(*signer) {
                return false;
            }
            if PeerId::from_ed25519_pub(ed25519_public) != *signer {
                return false;
            }
            verify(ed25519_public, DOMAIN_GROUP_GOVERNANCE, &message, signature)
        }
        GovernanceProof::Ring { ring_signature } => {
            if proposal.proposer.is_some() {
                return false;
            }
            ring.map(|public_ring| ring_verify(public_ring, &message, ring_signature))
                .unwrap_or(false)
        }
    }
}

fn governance_attributed_proof(
    secret_key: &[u8; 32],
    signer: &PeerId,
    message: Vec<u8>,
) -> GovernanceProof {
    let signing_key = SigningKey::from_bytes(secret_key);
    let ed25519_public = signing_key.verifying_key().to_bytes();
    let signature = sign(secret_key, DOMAIN_GROUP_GOVERNANCE, &message);
    GovernanceProof::Attributed {
        signer: *signer,
        ed25519_public,
        signature,
    }
}

fn proposal_message(
    proposal_id: &[u8; 16],
    group_id: &[u8; 16],
    action: &GovernanceAction,
    created_at: u64,
    expires_at: u64,
) -> Result<Vec<u8>, MeshError> {
    let action_bytes = serde_json::to_vec(action)
        .map_err(|e| MeshError::Internal(format!("failed to encode governance action: {e}")))?;
    let mut message = Vec::with_capacity(64 + action_bytes.len());
    message.extend_from_slice(proposal_id);
    message.extend_from_slice(group_id);
    message.extend_from_slice(&created_at.to_le_bytes());
    message.extend_from_slice(&expires_at.to_le_bytes());
    message.extend_from_slice(&(action_bytes.len() as u64).to_le_bytes());
    message.extend_from_slice(&action_bytes);
    Ok(message)
}

/// Check if a proposal has expired and update its status.
///
/// Should be called periodically (e.g., when the group is accessed)
/// to transition expired proposals from Open to Expired. Once expired,
/// the proposal is effectively rejected — the proposed action is not taken.
pub fn check_expiry(proposal: &mut Proposal, now_unix: u64) {
    // Only check Open proposals — decided proposals don't expire.
    if proposal.status != ProposalStatus::Open {
        return;
    }

    // If the current time is past the proposal's expiry, mark it Expired.
    // The proposed action will not be executed.
    if now_unix >= proposal.expires_at {
        proposal.status = ProposalStatus::Expired;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute ceil(fraction * count) as a usize.
///
/// Uses integer arithmetic to avoid floating-point rounding errors.
/// The result is the minimum number of votes/approvals needed to
/// meet the given fractional threshold.
fn ceiling_fraction(fraction: f64, count: usize) -> usize {
    // Multiply and ceil to get the minimum integer that satisfies the threshold.
    // f64 has enough precision for group sizes up to millions of members.
    let product = fraction * (count as f64);

    // Ceil ensures we round up — 2.01 becomes 3, not 2.
    // This prevents rounding down from weakening quorum requirements.
    product.ceil() as usize
}

/// Get the current Unix timestamp in seconds.
///
/// Uses `std::time::SystemTime` for portability across platforms.
/// Falls back to 0 if the system clock is before the Unix epoch
/// (which should never happen on a properly configured system).
fn current_unix_timestamp() -> u64 {
    // Get the current time from the system clock.
    // This is the standard Rust approach for Unix timestamps.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // If the clock is before epoch, return 0 rather than panicking.
        // This is safer than unwrap() in production code.
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Create an Ed25519 keypair for testing.
    /// Returns (secret_key, public_key) as 32-byte arrays.
    fn test_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        // Deterministic seed — each test peer gets a unique keypair.
        let mut secret = [0u8; 32];
        secret[0] = seed;
        // Derive the public key from the secret key.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key().to_bytes();
        (secret, public)
    }

    /// Create a PeerId from a public key.
    fn peer_id(public: &[u8; 32]) -> PeerId {
        PeerId::from_ed25519_pub(public)
    }

    /// Create a default policy for testing.
    fn test_policy() -> GovernancePolicy {
        GovernancePolicy::default_policy()
    }

    /// Create a proposal for testing with a known ID and timestamps.
    fn test_proposal(
        group_id: &[u8; 16],
        proposer: &PeerId,
        proposer_secret: &[u8; 32],
        action: GovernanceAction,
    ) -> Proposal {
        let created_at = 1000;
        let expires_at = 1000 + DEFAULT_VOTING_PERIOD_SECS;
        let proof = governance_attributed_proof(
            proposer_secret,
            proposer,
            proposal_message(&[1u8; 16], group_id, &action, created_at, expires_at).unwrap(),
        );
        Proposal {
            id: [1u8; 16],
            group_id: *group_id,
            proposer: Some(*proposer),
            proposer_proof: proof,
            action,
            created_at,
            expires_at,
            votes: Vec::new(),
            status: ProposalStatus::Open,
        }
    }

    // -----------------------------------------------------------------------
    // Proposal creation tests
    // -----------------------------------------------------------------------

    /// Test that admins can create proposals for all action types.
    #[test]
    fn test_create_proposal_admin_all_actions() {
        let group_id = [0xAA; 16];
        let (secret_key, pub_key) = test_keypair(1);
        let proposer = peer_id(&pub_key);
        let policy = test_policy();

        // Admins should be able to create any proposal type.
        let actions = vec![
            GovernanceAction::RemoveMember {
                peer_id: peer_id(&[0u8; 32]),
            },
            GovernanceAction::ChangeRole {
                peer_id: peer_id(&[0u8; 32]),
                new_role: GroupRole::Moderator,
            },
            GovernanceAction::ChangePolicy {
                new_policy: GovernancePolicy::default_policy(),
            },
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
            GovernanceAction::Dissolve,
        ];

        // Each action type should succeed for an admin proposer.
        for action in actions {
            let result = create_proposal(
                &group_id,
                &proposer,
                &GroupRole::Admin,
                action,
                &policy,
                &secret_key,
            );
            // Admin can propose everything — no errors expected.
            assert!(result.is_ok(), "admin should create any proposal");
            let p = result.expect("checked above");
            // The proposal should start in Open status with no votes.
            assert_eq!(p.status, ProposalStatus::Open);
            assert!(p.votes.is_empty());
            assert_eq!(p.group_id, group_id);
        }
    }

    /// Test that moderators can create ChangeRole and ChangeSettings
    /// proposals but NOT RemoveMember, Dissolve, or ChangePolicy.
    #[test]
    fn test_create_proposal_moderator_restrictions() {
        let group_id = [0xBB; 16];
        let (secret_key, pub_key) = test_keypair(2);
        let proposer = peer_id(&pub_key);
        let policy = test_policy();

        // Moderators CAN propose ChangeRole.
        let result = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Moderator,
            GovernanceAction::ChangeRole {
                peer_id: peer_id(&[0u8; 32]),
                new_role: GroupRole::Member,
            },
            &policy,
            &secret_key,
        );
        assert!(result.is_ok(), "moderator should propose ChangeRole");

        // Moderators CAN propose ChangeSettings.
        let result = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Moderator,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
            &policy,
            &secret_key,
        );
        assert!(result.is_ok(), "moderator should propose ChangeSettings");

        // Moderators CANNOT propose RemoveMember.
        let result = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Moderator,
            GovernanceAction::RemoveMember {
                peer_id: peer_id(&[0u8; 32]),
            },
            &policy,
            &secret_key,
        );
        assert!(result.is_err(), "moderator should not propose RemoveMember");

        // Moderators CANNOT propose Dissolve.
        let result = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Moderator,
            GovernanceAction::Dissolve,
            &policy,
            &secret_key,
        );
        assert!(result.is_err(), "moderator should not propose Dissolve");

        // Moderators CANNOT propose ChangePolicy.
        let result = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Moderator,
            GovernanceAction::ChangePolicy {
                new_policy: GovernancePolicy::default_policy(),
            },
            &policy,
            &secret_key,
        );
        assert!(result.is_err(), "moderator should not propose ChangePolicy");
    }

    /// Test that regular members cannot create any proposals.
    #[test]
    fn test_create_proposal_member_rejected() {
        let group_id = [0xCC; 16];
        let (secret_key, pub_key) = test_keypair(3);
        let proposer = peer_id(&pub_key);
        let policy = test_policy();

        // Members are not in the default proposer_roles list.
        // Every action type should be rejected.
        let result = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Member,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
            &policy,
            &secret_key,
        );
        assert!(result.is_err(), "members should not create proposals");
    }

    // -----------------------------------------------------------------------
    // Voting flow tests
    // -----------------------------------------------------------------------

    /// Test the full voting flow: create proposal, cast votes, reach approval.
    #[test]
    fn test_full_voting_flow_approval() {
        let group_id = [0xDD; 16];
        let (sk1, pk1) = test_keypair(10);
        let (sk2, pk2) = test_keypair(11);
        let (_, pk3) = test_keypair(12);

        let proposer = peer_id(&pk1);
        let voter1 = peer_id(&pk2);
        let _voter2 = peer_id(&pk3);

        let policy = test_policy();

        // Create a proposal for changing settings.
        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: r#"{"name":"new"}"#.to_string(),
            },
        );

        // 3 eligible voters, quorum = ceil(0.5 * 3) = 2 votes needed.
        // Approval threshold = ceil(0.67 * votes_cast).
        let eligible = 3;

        // First vote: proposer approves.
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        );
        assert!(result.is_ok(), "first vote should succeed");
        // Only 1 vote cast, quorum needs 2 — still Open.
        assert_eq!(proposal.status, ProposalStatus::Open);

        // Second vote: voter1 approves.
        let result = cast_vote(
            &mut proposal,
            &voter1,
            &GroupRole::Member,
            VoteDecision::Approve,
            &sk2,
            &policy,
            eligible,
        );
        assert!(result.is_ok(), "second vote should succeed");
        // 2 votes cast (quorum met), 2 approvals.
        // ceil(0.67 * 2) = 2 approvals needed. We have 2. Approved!
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    /// Test that a proposal stays Open when quorum is not met.
    #[test]
    fn test_quorum_not_met_stays_open() {
        let group_id = [0xEE; 16];
        let (sk1, pk1) = test_keypair(20);

        let proposer = peer_id(&pk1);
        let policy = test_policy();

        // Create a proposal.
        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // 10 eligible voters, quorum = ceil(0.5 * 10) = 5 votes needed.
        let eligible = 10;

        // Cast 1 approve vote — far below quorum.
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        );
        assert!(result.is_ok());
        // Only 1 of 10 voted — quorum (5) not met.
        assert_eq!(proposal.status, ProposalStatus::Open);
    }

    /// Test approval at exactly the threshold boundary.
    #[test]
    fn test_approval_at_exact_threshold() {
        let group_id = [0xFF; 16];
        let policy = GovernancePolicy {
            quorum: 0.5,
            // Set threshold to exactly 0.5 so 2 of 4 votes approves.
            approval_threshold: 0.5,
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            proposer_roles: vec![GroupRole::Admin, GroupRole::Moderator],
            voter_roles: vec![GroupRole::Admin, GroupRole::Moderator, GroupRole::Member],
        };

        // Create 4 voters with unique keypairs.
        let (sk1, pk1) = test_keypair(30);
        let (sk2, pk2) = test_keypair(31);
        let _ = test_keypair(32);
        let _ = test_keypair(33);

        let proposer = peer_id(&pk1);
        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        let eligible = 4;
        // quorum = ceil(0.5 * 4) = 2

        // Vote 1: approve
        cast_vote(
            &mut proposal,
            &peer_id(&pk1),
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote 1");

        // Vote 2: reject
        cast_vote(
            &mut proposal,
            &peer_id(&pk2),
            &GroupRole::Member,
            VoteDecision::Reject,
            &sk2,
            &policy,
            eligible,
        )
        .expect("vote 2");

        // 2 votes cast (quorum met), 1 approve, 1 reject.
        // ceil(0.5 * 2) = 1 approval needed. We have 1. Approved!
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    /// Test rejection when approval becomes mathematically impossible.
    #[test]
    fn test_rejection_impossible_approval() {
        let group_id = [0xAB; 16];
        let policy = test_policy(); // threshold = 0.67

        let (sk1, pk1) = test_keypair(40);
        let _ = test_keypair(41);
        let _ = test_keypair(42);

        let proposer = peer_id(&pk1);
        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // 3 eligible voters. approvals_needed_at_full = ceil(0.67 * 3) = 3.
        // max_rejections_allowed = 3 - 3 = 0.
        // So even 1 rejection should trigger early rejection.
        let eligible = 3;

        // Vote 1: reject
        cast_vote(
            &mut proposal,
            &peer_id(&pk1),
            &GroupRole::Admin,
            VoteDecision::Reject,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote 1");

        // With 1 rejection, max_possible_approvals = 0 + 2 = 2,
        // but we need 3. Also reject_count(1) > max_rejections_allowed(0).
        // Either check triggers Rejected.
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    // -----------------------------------------------------------------------
    // Expiry tests
    // -----------------------------------------------------------------------

    /// Test that check_expiry transitions Open proposals to Expired.
    #[test]
    fn test_expiry_handling() {
        let group_id = [0xCD; 16];
        let (_, pk1) = test_keypair(50);
        let proposer = peer_id(&pk1);

        // Create a proposal that expires at timestamp 1000 + 259200.
        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &[50; 32],
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // Before expiry — should stay Open.
        check_expiry(&mut proposal, 1000 + DEFAULT_VOTING_PERIOD_SECS - 1);
        assert_eq!(proposal.status, ProposalStatus::Open);

        // Exactly at expiry — should transition to Expired.
        check_expiry(&mut proposal, 1000 + DEFAULT_VOTING_PERIOD_SECS);
        assert_eq!(proposal.status, ProposalStatus::Expired);
    }

    /// Test that check_expiry does not affect already-decided proposals.
    #[test]
    fn test_expiry_does_not_affect_decided() {
        let group_id = [0xDE; 16];
        let (_, pk1) = test_keypair(51);
        let proposer = peer_id(&pk1);

        // Create a proposal and mark it Approved.
        let mut proposal =
            test_proposal(&group_id, &proposer, &[51; 32], GovernanceAction::Dissolve);
        proposal.status = ProposalStatus::Approved;

        // Even after expiry time, the status should remain Approved.
        let expiry_time = proposal.expires_at + 1_000_000;
        check_expiry(&mut proposal, expiry_time);
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Duplicate vote rejection
    // -----------------------------------------------------------------------

    /// Test that casting a duplicate vote is rejected.
    #[test]
    fn test_duplicate_vote_rejected() {
        let group_id = [0xEF; 16];
        let (sk1, pk1) = test_keypair(60);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // Use enough eligible voters that one vote won't decide.
        let eligible = 10;

        // First vote succeeds.
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        );
        assert!(result.is_ok(), "first vote should succeed");

        // Second vote from the same voter should fail.
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Reject,
            &sk1,
            &policy,
            eligible,
        );
        assert!(result.is_err(), "duplicate vote should be rejected");
        // Verify the error message mentions the duplicate.
        let err_msg = result.err().expect("checked above").to_string();
        assert!(
            err_msg.contains("already cast"),
            "error should mention duplicate: {}",
            err_msg,
        );
    }

    // -----------------------------------------------------------------------
    // Signature verification tests
    // -----------------------------------------------------------------------

    /// Test that vote signatures verify correctly.
    #[test]
    fn test_vote_signature_verification() {
        let group_id = [0xFA; 16];
        let (sk1, pk1) = test_keypair(70);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // Cast a vote (use enough eligible voters to keep it Open).
        let eligible = 10;
        cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote should succeed");

        // Verify the signature on the recorded vote.
        let vote = &proposal.votes[0];
        assert!(
            verify_vote_signature(&proposal.id, vote),
            "vote signature should be valid",
        );
    }

    /// Test that a forged vote signature fails verification.
    #[test]
    fn test_forged_signature_rejected() {
        let (_, pk1) = test_keypair(80);

        // Create a vote with a garbage signature.
        let forged_vote = Vote {
            decision: VoteDecision::Approve,
            proof: GovernanceProof::Attributed {
                signer: peer_id(&pk1),
                ed25519_public: pk1,
                signature: vec![0u8; 64],
            },
        };

        let proposal_id = [0xBB; 16];

        // The forged signature should fail verification.
        assert!(
            !verify_vote_signature(&proposal_id, &forged_vote),
            "forged signature should not verify",
        );
    }

    /// Test that a vote signature from a different proposal fails.
    #[test]
    fn test_cross_proposal_signature_rejected() {
        let group_id = [0xFC; 16];
        let (sk1, pk1) = test_keypair(90);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        let eligible = 10;
        cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote should succeed");

        // Try to verify the vote against a DIFFERENT proposal ID.
        let different_proposal_id = [0xFF; 16];
        let vote = &proposal.votes[0];
        assert!(
            !verify_vote_signature(&different_proposal_id, vote),
            "signature should fail for different proposal ID",
        );
    }

    // -----------------------------------------------------------------------
    // Role-based voting restrictions
    // -----------------------------------------------------------------------

    /// Test that a member with a non-voter role cannot cast a vote.
    #[test]
    fn test_non_voter_role_rejected() {
        let group_id = [0xAC; 16];
        let (sk1, pk1) = test_keypair(100);
        let proposer = peer_id(&pk1);

        // Create a policy where only Admins can vote.
        let policy = GovernancePolicy {
            quorum: 0.5,
            approval_threshold: 0.67,
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            proposer_roles: vec![GroupRole::Admin],
            voter_roles: vec![GroupRole::Admin], // Only admins vote
        };

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // A Member trying to vote should be rejected.
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Member, // Not in voter_roles
            VoteDecision::Approve,
            &sk1,
            &policy,
            5,
        );
        assert!(result.is_err(), "non-voter role should be rejected");
    }

    // -----------------------------------------------------------------------
    // Voting on non-Open proposals
    // -----------------------------------------------------------------------

    /// Test that votes on non-Open proposals are rejected.
    #[test]
    fn test_vote_on_non_open_rejected() {
        let group_id = [0xBC; 16];
        let (sk1, pk1) = test_keypair(110);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(&group_id, &proposer, &sk1, GovernanceAction::Dissolve);

        // Mark the proposal as Approved.
        proposal.status = ProposalStatus::Approved;

        // Voting on an Approved proposal should fail.
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            3,
        );
        assert!(result.is_err(), "should not vote on Approved proposal");

        // Also test Rejected status.
        proposal.status = ProposalStatus::Rejected;
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            3,
        );
        assert!(result.is_err(), "should not vote on Rejected proposal");

        // Also test Expired status.
        proposal.status = ProposalStatus::Expired;
        let result = cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            3,
        );
        assert!(result.is_err(), "should not vote on Expired proposal");
    }

    // -----------------------------------------------------------------------
    // Policy validation tests
    // -----------------------------------------------------------------------

    /// Test that invalid policy parameters are rejected.
    #[test]
    fn test_policy_validation() {
        // Zero quorum should fail.
        let mut policy = test_policy();
        policy.quorum = 0.0;
        assert!(policy.validate().is_err(), "zero quorum should fail");

        // Negative quorum should fail.
        policy.quorum = -0.1;
        assert!(policy.validate().is_err(), "negative quorum should fail");

        // Quorum > 1.0 should fail.
        policy.quorum = 1.1;
        assert!(policy.validate().is_err(), "quorum > 1.0 should fail");

        // Reset quorum, test threshold.
        policy.quorum = DEFAULT_QUORUM;

        // Zero threshold should fail.
        policy.approval_threshold = 0.0;
        assert!(policy.validate().is_err(), "zero threshold should fail",);

        // Reset threshold, test voting period.
        policy.approval_threshold = DEFAULT_APPROVAL_THRESHOLD;

        // Zero voting period should fail.
        policy.voting_period_secs = 0;
        assert!(policy.validate().is_err(), "zero voting period should fail",);

        // Reset voting period, test empty roles.
        policy.voting_period_secs = DEFAULT_VOTING_PERIOD_SECS;

        // Empty proposer roles should fail.
        policy.proposer_roles = vec![];
        assert!(
            policy.validate().is_err(),
            "empty proposer_roles should fail",
        );

        // Reset proposer roles, test empty voter roles.
        policy.proposer_roles = vec![GroupRole::Admin];
        policy.voter_roles = vec![];
        assert!(policy.validate().is_err(), "empty voter_roles should fail",);
    }

    /// Test that the default policy is valid.
    #[test]
    fn test_default_policy_valid() {
        let policy = GovernancePolicy::default_policy();
        assert!(policy.validate().is_ok(), "default policy should be valid");
    }

    // -----------------------------------------------------------------------
    // Ceiling fraction helper tests
    // -----------------------------------------------------------------------

    /// Test the ceiling_fraction helper with known values.
    #[test]
    fn test_ceiling_fraction() {
        // 50% of 3 = 1.5, ceil = 2
        assert_eq!(ceiling_fraction(0.5, 3), 2);

        // 67% of 3 = 2.01, ceil = 3
        assert_eq!(ceiling_fraction(0.67, 3), 3);

        // 50% of 4 = 2.0, ceil = 2
        assert_eq!(ceiling_fraction(0.5, 4), 2);

        // 67% of 4 = 2.68, ceil = 3
        assert_eq!(ceiling_fraction(0.67, 4), 3);

        // 50% of 1 = 0.5, ceil = 1
        assert_eq!(ceiling_fraction(0.5, 1), 1);

        // 100% of 5 = 5.0, ceil = 5
        assert_eq!(ceiling_fraction(1.0, 5), 5);
    }

    // -----------------------------------------------------------------------
    // Tally edge cases
    // -----------------------------------------------------------------------

    /// Test tallying with a single eligible voter (edge case).
    #[test]
    fn test_tally_single_voter() {
        let group_id = [0xDA; 16];
        let (sk1, pk1) = test_keypair(120);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // 1 eligible voter. quorum = ceil(0.5 * 1) = 1.
        // threshold = ceil(0.67 * 1) = 1 approval needed.
        let eligible = 1;

        // Single approve vote should approve.
        cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote should succeed");

        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    /// Test that all-reject votes result in rejection.
    #[test]
    fn test_tally_all_reject() {
        let group_id = [0xDB; 16];
        let (sk1, pk1) = test_keypair(130);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // 2 eligible voters.
        let eligible = 2;

        // Single reject vote — with threshold 0.67, needed at full =
        // ceil(0.67 * 2) = 2. max_rejections_allowed = 2 - 2 = 0.
        // So 1 rejection triggers early rejection.
        cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Reject,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote should succeed");

        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    /// Test that mixed votes with enough approvals pass.
    #[test]
    fn test_tally_mixed_votes_approval() {
        let group_id = [0xDC; 16];
        let policy = GovernancePolicy {
            quorum: 0.5,
            // Use a simple majority threshold (51%).
            approval_threshold: 0.51,
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            proposer_roles: vec![GroupRole::Admin, GroupRole::Moderator],
            voter_roles: vec![GroupRole::Admin, GroupRole::Moderator, GroupRole::Member],
        };

        let (sk1, pk1) = test_keypair(140);
        let (sk2, pk2) = test_keypair(141);
        let (sk3, pk3) = test_keypair(142);
        let _ = test_keypair(143);

        let proposer = peer_id(&pk1);
        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // 4 eligible voters. quorum = ceil(0.5 * 4) = 2.
        let eligible = 4;

        // Vote: approve, reject, approve — quorum met at vote 2.
        cast_vote(
            &mut proposal,
            &peer_id(&pk1),
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote 1");

        cast_vote(
            &mut proposal,
            &peer_id(&pk2),
            &GroupRole::Member,
            VoteDecision::Reject,
            &sk2,
            &policy,
            eligible,
        )
        .expect("vote 2");

        // After 2 votes: 1 approve, 1 reject. quorum met.
        // ceil(0.51 * 2) = 2 approvals needed. Only 1. Still Open.
        assert_eq!(proposal.status, ProposalStatus::Open);

        // Third vote: approve.
        cast_vote(
            &mut proposal,
            &peer_id(&pk3),
            &GroupRole::Member,
            VoteDecision::Approve,
            &sk3,
            &policy,
            eligible,
        )
        .expect("vote 3");

        // After 3 votes: 2 approve, 1 reject.
        // ceil(0.51 * 3) = 2 approvals needed. We have 2. Approved!
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    // -----------------------------------------------------------------------
    // Create proposal via public API (with RNG)
    // -----------------------------------------------------------------------

    /// Test that create_proposal generates a valid proposal with a random ID.
    #[test]
    fn test_create_proposal_generates_id() {
        let group_id = [0xAA; 16];
        let (sk1, pk1) = test_keypair(150);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let p1 = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Admin,
            GovernanceAction::Dissolve,
            &policy,
            &sk1,
        )
        .expect("should create proposal");

        let p2 = create_proposal(
            &group_id,
            &proposer,
            &GroupRole::Admin,
            GovernanceAction::Dissolve,
            &policy,
            &sk1,
        )
        .expect("should create second proposal");

        // Two proposals should have different IDs (with overwhelming probability).
        assert_ne!(p1.id, p2.id, "proposal IDs should be unique");

        // Both should have valid expiry times.
        assert!(p1.expires_at > p1.created_at);
        assert!(p2.expires_at > p2.created_at);

        // Both should be Open with no votes.
        assert_eq!(p1.status, ProposalStatus::Open);
        assert_eq!(p2.status, ProposalStatus::Open);
        assert!(p1.votes.is_empty());
        assert!(p2.votes.is_empty());
    }

    // -----------------------------------------------------------------------
    // MED-3: Tally rejects forged vote signatures
    // -----------------------------------------------------------------------

    /// Verify that tally_votes excludes votes with forged signatures.
    /// A vote injected directly into the proposal's Vec (bypassing
    /// cast_vote) with an invalid signature must not count toward
    /// quorum or approval thresholds.
    #[test]
    fn test_tally_rejects_forged_votes() {
        let group_id = [0xFE; 16];
        let (sk1, pk1) = test_keypair(200);
        let (_, pk2) = test_keypair(201);
        let proposer = peer_id(&pk1);
        let policy = test_policy();

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        // Cast one legitimate vote (signed with the correct key).
        // Use enough eligible voters so one vote alone won't decide.
        let eligible = 3;
        cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("legitimate vote should succeed");

        // Inject a forged vote directly into the Vec (simulating an
        // attacker who has write access to the proposal storage but
        // does not possess voter2's Ed25519 private key).
        let forged_vote = Vote {
            decision: VoteDecision::Approve,
            proof: GovernanceProof::Attributed {
                signer: peer_id(&pk2),
                ed25519_public: pk2,
                signature: vec![0xDE; 64],
            },
        };
        proposal.votes.push(forged_vote);

        // Reset status to Open so tally_votes re-evaluates.
        proposal.status = ProposalStatus::Open;

        // Tally should ignore the forged vote. With only 1 verified
        // vote out of 3 eligible, quorum (ceil(0.5 * 3) = 2) is not
        // met, so the proposal stays Open.
        let result = tally_votes(&mut proposal, &policy, eligible);
        assert_eq!(
            result,
            ProposalStatus::Open,
            "forged vote must not count toward quorum or threshold"
        );
    }

    /// Verify that tally_votes correctly approves when all votes have
    /// valid signatures (regression test to ensure signature verification
    /// does not accidentally reject legitimate votes).
    #[test]
    fn test_tally_accepts_valid_signatures() {
        let group_id = [0xFD; 16];
        let (sk1, pk1) = test_keypair(210);
        let (sk2, pk2) = test_keypair(211);
        let proposer = peer_id(&pk1);
        let voter = peer_id(&pk2);

        // Use a policy with low thresholds so 2 votes can approve.
        let policy = GovernancePolicy {
            quorum: 0.5,
            approval_threshold: 0.5,
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            proposer_roles: vec![GroupRole::Admin, GroupRole::Moderator],
            voter_roles: vec![GroupRole::Admin, GroupRole::Moderator, GroupRole::Member],
        };

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        let eligible = 3; // quorum = 2, threshold = ceil(0.5 * 2) = 1

        // Two legitimate votes should approve.
        cast_vote(
            &mut proposal,
            &proposer,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &policy,
            eligible,
        )
        .expect("vote 1");

        cast_vote(
            &mut proposal,
            &voter,
            &GroupRole::Member,
            VoteDecision::Approve,
            &sk2,
            &policy,
            eligible,
        )
        .expect("vote 2");

        // Both votes have valid signatures. With 2 of 3 eligible voting
        // and both approving, the proposal should be Approved.
        assert_eq!(
            proposal.status,
            ProposalStatus::Approved,
            "proposal with valid signatures should be approved"
        );
    }

    #[test]
    fn test_ring_proposal_verification() {
        let group_id = [0x91; 16];
        let policy = test_policy();
        let (sk1, pk1) = test_keypair(220);
        let (_, pk2) = test_keypair(221);
        let ring = vec![pk1, pk2];

        let proposal = create_ring_proposal(
            &group_id,
            &GroupRole::Admin,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
            &policy,
            &sk1,
            &ring,
        )
        .expect("ring proposal should succeed");

        assert!(proposal.proposer.is_none());
        assert!(verify_proposal_signature(&proposal, Some(&ring)));
        assert!(!verify_proposal_signature(&proposal, None));
    }

    #[test]
    fn test_ring_vote_verification_and_tally() {
        let group_id = [0x92; 16];
        let policy = GovernancePolicy {
            quorum: 0.5,
            approval_threshold: 0.5,
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            proposer_roles: vec![GroupRole::Admin, GroupRole::Moderator],
            voter_roles: vec![GroupRole::Admin, GroupRole::Moderator, GroupRole::Member],
        };
        let (sk1, pk1) = test_keypair(230);
        let (sk2, pk2) = test_keypair(231);
        let ring = vec![pk1, pk2];
        let proposer = peer_id(&pk1);

        let mut proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );

        cast_ring_vote(
            &mut proposal,
            &GroupRole::Admin,
            VoteDecision::Approve,
            &sk1,
            &ring,
            &policy,
            2,
        )
        .expect("first ring vote");
        assert!(verify_vote_signature_with_ring(
            &proposal.id,
            &proposal.votes[0],
            Some(&ring)
        ));
        assert_eq!(proposal.status, ProposalStatus::Approved);

        let mut second_proposal = test_proposal(
            &group_id,
            &proposer,
            &sk1,
            GovernanceAction::ChangeSettings {
                settings_json: "{}".to_string(),
            },
        );
        cast_ring_vote(
            &mut second_proposal,
            &GroupRole::Member,
            VoteDecision::Approve,
            &sk2,
            &ring,
            &policy,
            2,
        )
        .expect("second ring vote");
        assert!(verify_vote_signature_with_ring(
            &second_proposal.id,
            &second_proposal.votes[0],
            Some(&ring),
        ));
    }
}
