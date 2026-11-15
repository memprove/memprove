//! Claim references of `checkpoint create --supersedes/--withdraw/--reaffirm`
//! and `decide --supersedes` (ADR 0013 D1, P3-C).
//!
//! A reference is a Task-local number (`3` or `#3`) or a claim ID. Numbers
//! are resolved against the Task Capsule read just before the request; the
//! CLI refuses to resolve against a `tampered` Capsule, whose readable claims
//! may be fewer, and refuses a number the Capsule does not list. Nothing is
//! sent then. Claim IDs go to the daemon as given; it checks them.

use std::fmt::{self, Write as _};

use memprove_protocol::strict_json::{JsonValue, parse_strict};

use memprove_domain::{
    ClaimKind, ReaffirmSkip, RunKind, Standing, StateRun, StateSkip, Verdict, awaits_reaffirmation,
    match_reaffirmation, runs_are_current,
};

use crate::{
    context::{RunLabel, argv_digest},
    display::command,
    json_string,
};

#[path = "reaffirm_all.rs"]
mod reaffirm_all;
pub use reaffirm_all::{
    Outcome as ReaffirmOutcome, ReaffirmAllReport, SkipCode, WARNING_OTHER_COMMANDS,
};

/// One claim reference as given on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRef {
    /// A Task-local number of the current Task Capsule.
    Number(u64),
    /// A claim ID: `<checkpoint_id>/<section>/<ordinal>` or
    /// `decision/<event_id>`.
    Id(String),
}

impl ClaimRef {
    /// Parses `3`, `#3`, or a claim ID.
    ///
    /// # Errors
    ///
    /// A message naming `flag` when the value is neither.
    pub fn parse(value: &str, flag: &str) -> Result<Self, String> {
        let digits = value.strip_prefix('#').unwrap_or(value);
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return digits
                .parse::<u64>()
                .ok()
                .filter(|number| *number >= 1)
                .map(Self::Number)
                .ok_or_else(|| format!("{flag}: claim numbers start at 1"));
        }
        if is_claim_id(value) {
            Ok(Self::Id(value.to_owned()))
        } else {
            Err(format!(
                "{flag} takes a claim number from `memprove resume --text` (for example 3) \
                 or a claim ID (<checkpoint_id>/<section>/<ordinal> or decision/<event_id>)"
            ))
        }
    }
}

pub(crate) fn is_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

/// The ADR 0013 D1 claim ID spellings.
fn is_claim_id(value: &str) -> bool {
    if let Some(event_id) = value.strip_prefix("decision/") {
        return is_uuid_v7(event_id);
    }
    let parts = value.split('/').collect::<Vec<_>>();
    let [checkpoint_id, section, ordinal] = parts[..] else {
        return false;
    };
    is_uuid_v7(checkpoint_id)
        && matches!(
            section,
            "verified_completed_work" | "open_items" | "next_action"
        )
        && !ordinal.is_empty()
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
        && (ordinal.len() == 1 || !ordinal.starts_with('0'))
}

/// What a statement of `checkpoint create` is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementKind {
    /// `--fact <TEXT>`.
    Fact(String),
    /// `--open <TEXT>`.
    Open(String),
    /// `--reaffirm <REF>`: the referenced fact's text again, as a new fact
    /// on new Evidence that supersedes it.
    Reaffirm(ClaimRef),
    /// `--reaffirm-all` (P4-A): every fact that awaits reaffirmation, each
    /// as a `--reaffirm`; expanded through the Task Capsule
    /// ([`Draft::expand_reaffirm_all`]) before the body is built.
    ReaffirmAll,
}

/// One statement of `checkpoint create`, in command-line order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementDraft {
    /// What it is.
    pub kind: StatementKind,
    /// Its Evidence IDs.
    pub evidence: Vec<String>,
    /// The claims it supersedes.
    pub supersedes: Vec<ClaimRef>,
}

impl StatementDraft {
    /// Whether it is a `verified_fact`.
    #[must_use]
    pub const fn is_fact(&self) -> bool {
        !matches!(self.kind, StatementKind::Open(_))
    }
}

/// A `createCheckpoint` request before its claim references are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointDraft {
    /// `workspace_id`.
    pub workspace_id: String,
    /// `task_id`.
    pub task_id: String,
    /// `session_id`.
    pub session_id: String,
    /// `snapshot_id`, or (U9 K1, U8 V-N3) why there is none: when
    /// `--snapshot` is absent, the context records none, and
    /// `--withdraw-session` is given, the Task Capsule checks that `k`
    /// first and the reason is raised once it did. Without
    /// `--withdraw-session` it is raised before the request is drafted.
    pub snapshot_id: Result<String, Box<str>>,
    /// `objective`.
    pub objective: String,
    /// `--fact`, `--open`, and `--reaffirm`, in order.
    pub statements: Vec<StatementDraft>,
    /// `--next`.
    pub next: String,
    /// The claims `--next` supersedes.
    pub next_supersedes: Vec<ClaimRef>,
    /// `--withdraw`.
    pub withdrawals: Vec<ClaimRef>,
    /// `--withdraw-reason`: why the withdrawn claims no longer hold; the
    /// daemon requires it when one of them is a fact (P3-D2).
    pub withdrawal_reason: Option<String>,
    /// U8 A5 (Owner O4): `--withdraw-session <k>`: every statement `Session k`
    /// wrote that is still in force is withdrawn too, resolved through the
    /// Task Capsule.
    pub withdraw_session: Option<u64>,
    /// The runs of the current repository state the context records, in
    /// label order: what `--reaffirm-all` without `--evidence` matches the
    /// commands of a fact's Evidence against (P4-A).
    pub state_runs: Vec<RunLabel>,
    /// The `capture_manifest_digest` of the Snapshot those runs belong to,
    /// when the context records it and the Checkpoint is sealed on that
    /// Snapshot (P4-A).
    pub state_manifest: Option<String>,
    /// The Workspace of the context those runs belong to (P4-B, T18 N-c):
    /// runs of another Workspace than the Checkpoint's answer for nothing.
    pub state_workspace: Option<String>,
}

/// A `proposeDecision` request before its claim references are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDraft {
    /// `task_id`.
    pub task_id: String,
    /// `session_id`.
    pub session_id: String,
    /// `content`.
    pub content: String,
    /// `rationale`.
    pub rationale: Option<String>,
    /// `evidence_ids`.
    pub evidence: Vec<String>,
    /// `supersedes`.
    pub supersedes: Vec<ClaimRef>,
}

/// A request whose body is built from a draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Draft {
    /// `checkpoint create` with flags.
    Checkpoint(CheckpointDraft),
    /// `decide`.
    Decision(DecisionDraft),
}

/// One claim of a Task Capsule, as a reference resolves it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    number: u64,
    claim_id: String,
    kind: String,
    text: String,
    standing: String,
    /// Its verdict, when the Capsule gives one.
    verdict: Option<String>,
    /// The argv and kind of each cited Evidence, in citation order; `None`
    /// for Evidence that is not a command or test run (P4-A; the kind,
    /// P4-B).
    commands: Vec<Option<(Vec<String>, RunKind)>>,
    /// U8 A5: the Session that wrote it.
    session_id: Option<String>,
}

/// U8 A5 (Owner O4): the most claims one `--withdraw-session` expands to,
/// the limit the MCP `checkpoint` tool puts on `withdraw` (500).
pub const WITHDRAW_SESSION_LIMIT: usize = 500;

/// The claims of a Task Capsule a reference can name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleClaims {
    /// Every listed claim.
    claims: Vec<Listed>,
    /// The `capture_manifest_digest` of the probed Workspace, when it was
    /// observed: the current repository state (P4-A).
    probe_manifest: Option<String>,
    /// The text of the next action in force, when one is (P4-B).
    next_action: Option<String>,
    /// U8 A5: the Capsule's Sessions, in order (`Session k` is the k-th).
    sessions: Vec<String>,
}

impl CapsuleClaims {
    /// Reads the claims of a Task Capsule body.
    ///
    /// # Errors
    ///
    /// When the body is not a Task Capsule, or the Capsule is `tampered`:
    /// its readable claims may be fewer than the ledger's, so numbers are
    /// not resolved against it.
    pub fn from_body(body: &str) -> Result<Self, CapsuleError> {
        let capsule = parse_strict(body).map_err(|_| CapsuleError::NotJson)?;
        let text = |value: &JsonValue, name: &str| {
            value
                .get(name)
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        };
        if text(&capsule, "status").as_deref() == Some("tampered") {
            let reasons = capsule
                .get("reasons")
                .and_then(JsonValue::as_array)
                .map(|reasons| {
                    reasons
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            return Err(CapsuleError::Tampered(reasons));
        }
        let claims = capsule
            .get("claims")
            .and_then(JsonValue::as_array)
            .ok_or(CapsuleError::NoClaims)?
            .iter()
            .map(|claim| {
                Some(Listed {
                    number: claim
                        .get("number")
                        .and_then(JsonValue::as_i64)
                        .and_then(|number| u64::try_from(number).ok())?,
                    claim_id: text(claim, "claim_id")?,
                    kind: text(claim, "kind")?,
                    text: text(claim, "text")?,
                    standing: text(claim, "standing")?,
                    verdict: text(claim, "verdict"),
                    commands: cited_commands(claim),
                    session_id: text(claim, "session_id"),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(CapsuleError::Unreadable)?;
        let probe = capsule
            .get("bindings")
            .and_then(|bindings| bindings.get("probe"));
        let probe_manifest = probe
            .filter(|probe| probe.get("available").and_then(JsonValue::as_bool) == Some(true))
            .and_then(|probe| text(probe, "capture_manifest_digest"));
        let next_action = claims
            .iter()
            .rfind(|claim| claim.kind == "next_action" && claim.standing == "active")
            .map(|claim| claim.text.clone());
        let sessions = capsule
            .get("sessions")
            .and_then(JsonValue::as_array)
            .unwrap_or_default()
            .iter()
            .map(|session| text(session, "session_id").unwrap_or_default())
            .collect();
        Ok(Self {
            claims,
            probe_manifest,
            next_action,
            sessions,
        })
    }

    /// U24 (I1): the text of every open item in force, in claim order.
    #[must_use]
    pub fn open_items_in_force(&self) -> Vec<&str> {
        self.claims
            .iter()
            .filter(|claim| claim.kind == "open_item" && claim.standing == "active")
            .map(|claim| claim.text.as_str())
            .collect()
    }

    /// U24 (I1): the text of the next action in force, when one is.
    #[must_use]
    pub fn next_action_in_force(&self) -> Option<&str> {
        self.next_action.as_deref()
    }

    /// U8 A5 (Owner O4): the claim IDs of every statement `Session number`
    /// wrote that is still in force, in claim order.
    ///
    /// # Errors
    ///
    /// When `number` names no Session of the Capsule, when the Session has
    /// no statement in force, or when it has more than
    /// [`WITHDRAW_SESSION_LIMIT`].
    fn session_statements(&self, number: u64) -> Result<Vec<String>, ClaimError> {
        let session_id = usize::try_from(number)
            .ok()
            .and_then(|number| number.checked_sub(1))
            .and_then(|index| self.sessions.get(index))
            .ok_or(ClaimError::NoSuchSession {
                number,
                total: self.sessions.len(),
            })?;
        let ids = self
            .claims
            .iter()
            .filter(|claim| {
                claim.standing == "active" && claim.session_id.as_ref() == Some(session_id)
            })
            .map(|claim| claim.claim_id.clone())
            .collect::<Vec<_>>();
        match ids.len() {
            0 => Err(ClaimError::NothingInForce(number)),
            count if count > WITHDRAW_SESSION_LIMIT => {
                Err(ClaimError::TooManyInForce { number, count })
            }
            _ => Ok(ids),
        }
    }

    fn by_number(&self, number: u64) -> Result<&Listed, ClaimError> {
        self.claims
            .iter()
            .find(|claim| claim.number == number)
            .ok_or_else(|| ClaimError::NotListed {
                number,
                first: self.claims.first().map(|claim| claim.number),
                last: self.claims.last().map(|claim| claim.number),
            })
    }

    fn by_id(&self, claim_id: &str) -> Result<&Listed, ClaimError> {
        self.claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
            .ok_or_else(|| ClaimError::IdNotListed(claim_id.to_owned()))
    }

    /// P4-G (ADR 0014 E7.5.6): the claim number of `claim_id`, when the
    /// Capsule lists it.
    #[must_use]
    pub fn number_of(&self, claim_id: &str) -> Option<u64> {
        self.claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
            .map(|claim| claim.number)
    }
}

/// Why a Task Capsule body cannot resolve claim references (P4-G: the MCP
/// server tells these cases apart; [`fmt::Display`] is what the CLI prints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    /// The body is not JSON.
    NotJson,
    /// The Capsule is `tampered`, with its reason codes joined by `, `.
    Tampered(String),
    /// The Capsule has no `claims` member.
    NoClaims,
    /// A claim of the Capsule lacks a member a reference needs.
    Unreadable,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson => formatter.write_str("the Task Capsule is not JSON"),
            Self::Tampered(reasons) => write!(
                formatter,
                "the Task Capsule is tampered ({reasons}): a damaged record may hide claims, so \
                 claim numbers are not resolved against it and nothing was sent. Run `memprove \
                 resume --text` to see the damaged records, and `memprove ledger verify`"
            ),
            Self::NoClaims => formatter.write_str("the Task Capsule lists no claims member"),
            Self::Unreadable => formatter.write_str("a claim of the Task Capsule is not readable"),
        }
    }
}

/// Why a claim reference did not resolve (P4-G: the MCP server maps each
/// case to a tool error; [`fmt::Display`] is what the CLI prints). Nothing
/// is sent in any of these cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// A number the Capsule does not list, with the first and last numbers
    /// it lists.
    NotListed {
        /// The number.
        number: u64,
        /// The first number listed, when there is one.
        first: Option<u64>,
        /// The last number listed, when there is one.
        last: Option<u64>,
    },
    /// A claim ID the Capsule does not list.
    IdNotListed(String),
    /// A number, and no Capsule to resolve it.
    NeedsCapsule(u64),
    /// A `--reaffirm`, and no Capsule.
    ReaffirmNeedsCapsule,
    /// A `--reaffirm-all` that was not expanded.
    ReaffirmAllNeedsCapsule,
    /// `--reaffirm` of a claim that is not a fact, and its kind.
    NotAFact {
        /// The claim's number.
        number: u64,
        /// Its kind.
        kind: String,
    },
    /// `--reaffirm` of a fact that is not active, and its standing.
    NotActive {
        /// The claim's number.
        number: u64,
        /// Its standing.
        standing: String,
    },
    /// U8 A5: `--withdraw-session` names no Session of the Capsule.
    NoSuchSession {
        /// The number given.
        number: u64,
        /// How many Sessions the Capsule lists.
        total: usize,
    },
    /// U8 A5: the Session has no statement in force.
    NothingInForce(u64),
    /// U8 A5: the Session has more statements in force than one request
    /// withdraws.
    TooManyInForce {
        /// The Session's number.
        number: u64,
        /// How many it has.
        count: usize,
    },
    /// U9 K1: `--withdraw-session` was valid, and the checkpoint has no
    /// Snapshot to be sealed on (the usage error that names why).
    SnapshotRequired(String),
}

impl ClaimError {
    /// U8 A5: whether the error is a usage error (exit 2) of
    /// `--withdraw-session`.
    #[must_use]
    pub const fn is_usage(&self) -> bool {
        matches!(
            self,
            Self::NoSuchSession { .. }
                | Self::NothingInForce(_)
                | Self::TooManyInForce { .. }
                | Self::SnapshotRequired(_)
        )
    }
}

impl fmt::Display for ClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotListed {
                number,
                last: Some(last),
                ..
            } => write!(
                formatter,
                "claim #{number} is not in the Task Capsule, which lists #1 to #{last}; nothing \
                 was sent"
            ),
            Self::NotListed { number, .. } => write!(
                formatter,
                "claim #{number} is not in the Task Capsule, which lists no claim; nothing was sent"
            ),
            Self::IdNotListed(claim_id) => write!(
                formatter,
                "claim {claim_id} is not in the Task Capsule; nothing was sent"
            ),
            Self::NeedsCapsule(number) => write!(
                formatter,
                "claim #{number} needs the Task Capsule to resolve; nothing was sent"
            ),
            Self::ReaffirmNeedsCapsule => {
                formatter.write_str("--reaffirm needs the Task Capsule; nothing was sent")
            }
            Self::ReaffirmAllNeedsCapsule => formatter
                .write_str("--reaffirm-all needs the Task Capsule to expand; nothing was sent"),
            Self::NotAFact { number, kind } => write!(
                formatter,
                "--reaffirm #{number} names a {kind} claim; only a fact can be reaffirmed (use \
                 --supersedes or --withdraw for other claims); nothing was sent"
            ),
            Self::NotActive { number, standing } => write!(
                formatter,
                "--reaffirm #{number} names a fact that is {standing}; only an active fact can be \
                 reaffirmed (record a new --fact instead); nothing was sent"
            ),
            Self::NoSuchSession { number, total } => write!(
                formatter,
                "--withdraw-session {number} names no Session of this Task, which has {total} \
                 (Session 1 to Session {total}); nothing was sent"
            ),
            Self::NothingInForce(number) => write!(
                formatter,
                "--withdraw-session {number}: Session {number} has no statement in force to withdraw; \
                 nothing was sent"
            ),
            Self::TooManyInForce { number, count } => write!(
                formatter,
                "--withdraw-session {number}: Session {number} has {count} statements in force, more \
                 than the {WITHDRAW_SESSION_LIMIT} one Checkpoint withdraws; withdraw them with \
                 --withdraw <NUMBER> in several Checkpoints; nothing was sent"
            ),
            Self::SnapshotRequired(reason) => write!(formatter, "{reason}; nothing was sent"),
        }
    }
}

impl std::error::Error for ClaimError {}
impl std::error::Error for CapsuleError {}

/// The argv and run kind of each Evidence a Capsule claim cites, in
/// citation order; `None` for one that is not a command or test run.
fn cited_commands(claim: &JsonValue) -> Vec<Option<(Vec<String>, RunKind)>> {
    claim
        .get("evidence")
        .and_then(JsonValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|evidence| {
            let kind = evidence
                .get("kind")
                .and_then(JsonValue::as_str)
                .and_then(RunKind::of_evidence)?;
            let argv = evidence
                .get("argv")
                .and_then(JsonValue::as_array)
                .filter(|argv| !argv.is_empty())
                .and_then(|argv| {
                    argv.iter()
                        .map(|word| word.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                })?;
            Some((argv, kind))
        })
        .collect()
}

/// Resolves references: numbers through the Capsule, claim IDs as given.
struct Resolver<'a>(Option<&'a CapsuleClaims>);

impl Resolver<'_> {
    fn id(&self, reference: &ClaimRef) -> Result<String, ClaimError> {
        match (reference, self.0) {
            (ClaimRef::Id(id), _) => Ok(id.clone()),
            (ClaimRef::Number(number), Some(claims)) => {
                Ok(claims.by_number(*number)?.claim_id.clone())
            }
            (ClaimRef::Number(number), None) => Err(ClaimError::NeedsCapsule(*number)),
        }
    }

    fn ids(&self, references: &[ClaimRef]) -> Result<Vec<String>, ClaimError> {
        references
            .iter()
            .map(|reference| self.id(reference))
            .collect()
    }

    /// The text and claim ID of the fact `--reaffirm` names. P3-D2 (Owner,
    /// T13 N8): only an active fact; a superseded or withdrawn one has
    /// already been replaced or given up.
    fn fact(&self, reference: &ClaimRef) -> Result<(String, String), ClaimError> {
        let claims = self.0.ok_or(ClaimError::ReaffirmNeedsCapsule)?;
        let claim = match reference {
            ClaimRef::Number(number) => claims.by_number(*number)?,
            ClaimRef::Id(id) => claims.by_id(id)?,
        };
        if claim.kind != "fact" {
            return Err(ClaimError::NotAFact {
                number: claim.number,
                kind: claim.kind.clone(),
            });
        }
        if claim.standing != "active" {
            return Err(ClaimError::NotActive {
                number: claim.number,
                standing: claim.standing.clone(),
            });
        }
        Ok((claim.text.clone(), claim.claim_id.clone()))
    }
}

fn ids_json(ids: &[String]) -> String {
    format!(
        "[{}]",
        ids.iter()
            .map(|id| json_string(id))
            .collect::<Vec<_>>()
            .join(",")
    )
}

impl Draft {
    /// The Task whose Capsule resolves the references.
    #[must_use]
    pub fn task_id(&self) -> &str {
        match self {
            Self::Checkpoint(draft) => &draft.task_id,
            Self::Decision(draft) => &draft.task_id,
        }
    }

    /// The Workspace whose probe the Task Capsule must carry: the
    /// Checkpoint's, when `--reaffirm-all` compares runs with the current
    /// repository state (P4-A).
    #[must_use]
    pub fn probe_workspace(&self) -> Option<&str> {
        match self {
            Self::Checkpoint(draft)
                if draft
                    .statements
                    .iter()
                    .any(|statement| statement.kind == StatementKind::ReaffirmAll) =>
            {
                Some(&draft.workspace_id)
            }
            _ => None,
        }
    }

    /// Whether any reference is a number or a `--reaffirm`, which need the
    /// current Task Capsule.
    #[must_use]
    pub fn needs_capsule(&self) -> bool {
        let numbered = |references: &[ClaimRef]| {
            references
                .iter()
                .any(|reference| matches!(reference, ClaimRef::Number(_)))
        };
        match self {
            Self::Checkpoint(draft) => {
                numbered(&draft.next_supersedes)
                    || numbered(&draft.withdrawals)
                    || draft.withdraw_session.is_some()
                    || draft.statements.iter().any(|statement| {
                        matches!(
                            statement.kind,
                            StatementKind::Reaffirm(_) | StatementKind::ReaffirmAll
                        ) || numbered(&statement.supersedes)
                    })
            }
            Self::Decision(draft) => numbered(&draft.supersedes),
        }
    }

    /// The request body, with every reference resolved through `claims`
    /// (`None` when [`Draft::needs_capsule`] is false).
    ///
    /// # Errors
    ///
    /// A number the Capsule does not list, a `--reaffirm` of a claim that is
    /// not a fact, or a number without a Capsule.
    pub fn render(&self, claims: Option<&CapsuleClaims>) -> Result<String, ClaimError> {
        let resolver = Resolver(claims);
        match self {
            Self::Checkpoint(draft) => render_checkpoint(draft, &resolver),
            Self::Decision(draft) => {
                let mut body = format!(
                    r#"{{"schema_version":1,"task_id":{},"session_id":{},"content":{}"#,
                    json_string(&draft.task_id),
                    json_string(&draft.session_id),
                    json_string(&draft.content),
                );
                if let Some(rationale) = &draft.rationale {
                    write!(body, r#","rationale":{}"#, json_string(rationale))
                        .expect("writing to a String cannot fail");
                }
                if !draft.evidence.is_empty() {
                    write!(body, r#","evidence_ids":{}"#, ids_json(&draft.evidence))
                        .expect("writing to a String cannot fail");
                }
                let supersedes = resolver.ids(&draft.supersedes)?;
                if !supersedes.is_empty() {
                    write!(body, r#","supersedes":{}"#, ids_json(&supersedes))
                        .expect("writing to a String cannot fail");
                }
                body.push('}');
                Ok(body)
            }
        }
    }
}

impl Draft {
    /// For each `verified_fact` of a `checkpoint create` draft, in request
    /// order, whether it is a `--reaffirm` (P3-L L8); empty for a Decision.
    #[must_use]
    pub fn reaffirmed_facts(&self) -> Vec<bool> {
        match self {
            Self::Checkpoint(draft) => draft
                .statements
                .iter()
                .filter(|statement| statement.is_fact())
                .map(|statement| {
                    matches!(
                        statement.kind,
                        StatementKind::Reaffirm(_) | StatementKind::ReaffirmAll
                    )
                })
                .collect(),
            Self::Decision(_) => Vec::new(),
        }
    }
}

/// `#a, #b`, or `none`.
fn listed_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

/// `(old, new)` for each reaffirmed fact of the request: the first target
/// its `supersedes` names, and the new claim (P3-L L8).
fn reaffirmations(
    request: &JsonValue,
    checkpoint_id: &str,
    reaffirmed: &[bool],
    number_of: &impl Fn(&str) -> Option<i64>,
) -> Vec<(i64, i64)> {
    let facts = request
        .get("verified_completed_work")
        .and_then(JsonValue::as_array)
        .unwrap_or_default();
    facts
        .iter()
        .enumerate()
        .filter(|(index, _)| reaffirmed.get(*index).copied().unwrap_or(false))
        .filter_map(|(index, fact)| {
            let old = fact
                .get("supersedes")
                .and_then(JsonValue::as_array)
                .and_then(|targets| targets.first())
                .and_then(JsonValue::as_str)
                .and_then(number_of)?;
            let new = number_of(&format!("{checkpoint_id}/verified_completed_work/{index}"))?;
            Some((old, new))
        })
        .collect()
}

/// `(new, old)` for each claim a new claim supersedes, sorted, but for the
/// reaffirmations (P3-L L8).
fn supersessions(claims: &[JsonValue], fresh: &[i64], reaffirms: &[(i64, i64)]) -> Vec<(i64, i64)> {
    let mut superseded = claims
        .iter()
        .filter_map(|claim| Some((claim.get("number")?.as_i64()?, claim)))
        .flat_map(|(old, claim)| {
            claim
                .get("superseded_by")
                .and_then(JsonValue::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(|by| by.get("number").and_then(JsonValue::as_i64))
                .filter(move |new| fresh.contains(new) && !reaffirms.contains(&(old, *new)))
                .map(move |new| (new, old))
        })
        .collect::<Vec<_>>();
    superseded.sort_unstable();
    superseded
}

/// P3-L L8: what `checkpoint create` reports on standard error after the
/// Checkpoint `checkpoint_id` was recorded, read from the Task Capsule
/// after the write and the request that was sent: the number and kind of
/// each new statement, and the numbers each supersession (also of the
/// previous next action, which a new one replaces), withdrawal, and
/// reaffirmation touched. `reaffirmed` says, for each `verified_fact` of
/// the request in order, whether it was a `--reaffirm`; a reaffirmation is
/// reported as such, not again as a supersession.
///
/// # Errors
///
/// When the Capsule or the request is not JSON, or the Capsule lists no
/// claims.
pub fn checkpoint_report(
    capsule: &str,
    request: &str,
    checkpoint_id: &str,
    reaffirmed: &[bool],
) -> Result<Vec<String>, String> {
    CheckpointReport::read(capsule, request, checkpoint_id, reaffirmed).map(|report| report.lines())
}

/// What a recorded Checkpoint did (P3-L L8), as data (P4-G, ADR 0014
/// E7.5.6: the MCP `checkpoint` result; [`CheckpointReport::lines`] is what
/// `checkpoint create` prints).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckpointReport {
    /// `(number, kind)` of each new statement, in number order.
    pub fresh: Vec<(i64, String)>,
    /// `(new, old)` for each claim a new claim supersedes, sorted, but for
    /// the reaffirmations.
    pub superseded: Vec<(i64, i64)>,
    /// The numbers withdrawn, sorted.
    pub withdrawn: Vec<i64>,
    /// `(old, new)` for each reaffirmed fact.
    pub reaffirmed: Vec<(i64, i64)>,
}

impl CheckpointReport {
    /// Reads the report from the Task Capsule after the write (see
    /// [`checkpoint_report`]).
    ///
    /// # Errors
    ///
    /// When the Capsule or the request is not JSON, or the Capsule lists no
    /// claims.
    pub fn read(
        capsule: &str,
        request: &str,
        checkpoint_id: &str,
        reaffirmed: &[bool],
    ) -> Result<Self, String> {
        let capsule =
            parse_strict(capsule).map_err(|_| "the Task Capsule is not JSON".to_owned())?;
        let request = parse_strict(request).map_err(|_| "the request is not JSON".to_owned())?;
        let text = |value: &JsonValue, name: &str| {
            value
                .get(name)
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let claims = capsule
            .get("claims")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "the Task Capsule lists no claims member".to_owned())?;
        let number_of = |claim_id: &str| {
            claims
                .iter()
                .find(|claim| text(claim, "claim_id") == claim_id)
                .and_then(|claim| claim.get("number").and_then(JsonValue::as_i64))
        };
        let prefix = format!("{checkpoint_id}/");
        let mut fresh = claims
            .iter()
            .filter(|claim| text(claim, "claim_id").starts_with(&prefix))
            .filter_map(|claim| {
                Some((
                    claim.get("number").and_then(JsonValue::as_i64)?,
                    text(claim, "kind"),
                ))
            })
            .collect::<Vec<_>>();
        fresh.sort_unstable();
        let fresh_numbers = fresh.iter().map(|(number, _)| *number).collect::<Vec<_>>();
        let reaffirms = reaffirmations(&request, checkpoint_id, reaffirmed, &number_of);
        let superseded = supersessions(claims, &fresh_numbers, &reaffirms);
        let mut withdrawn = request
            .get("withdrawals")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .filter_map(JsonValue::as_str)
            .filter_map(number_of)
            .collect::<Vec<_>>();
        withdrawn.sort_unstable();
        Ok(Self {
            fresh,
            superseded,
            withdrawn,
            reaffirmed: reaffirms,
        })
    }

    /// The four lines `checkpoint create` prints.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let line = |label: &str, items: Vec<String>| format!("{label}: {}", listed_or_none(&items));
        vec![
            line(
                "new statements",
                self.fresh
                    .iter()
                    .map(|(number, kind)| format!("#{number} {kind}"))
                    .collect(),
            ),
            line(
                "superseded",
                self.superseded
                    .iter()
                    .map(|(new, old)| format!("#{old} by #{new}"))
                    .collect(),
            ),
            line(
                "withdrawn",
                self.withdrawn
                    .iter()
                    .map(|number| format!("#{number}"))
                    .collect(),
            ),
            line(
                "reaffirmed",
                self.reaffirmed
                    .iter()
                    .map(|(old, new)| format!("#{old} as #{new}"))
                    .collect(),
            ),
        ]
    }
}

fn render_checkpoint(
    draft: &CheckpointDraft,
    resolver: &Resolver<'_>,
) -> Result<String, ClaimError> {
    let statement = |item: &StatementDraft| -> Result<String, ClaimError> {
        let (classification, text, mut supersedes) = match &item.kind {
            StatementKind::Fact(text) => ("verified_fact", text.clone(), Vec::new()),
            StatementKind::Open(text) => ("unknown", text.clone(), Vec::new()),
            StatementKind::Reaffirm(reference) => {
                let (text, claim_id) = resolver.fact(reference)?;
                ("verified_fact", text, vec![claim_id])
            }
            StatementKind::ReaffirmAll => return Err(ClaimError::ReaffirmAllNeedsCapsule),
        };
        for id in resolver.ids(&item.supersedes)? {
            if !supersedes.contains(&id) {
                supersedes.push(id);
            }
        }
        let mut json = format!(
            r#"{{"classification":"{classification}","text":{}"#,
            json_string(&text)
        );
        if !item.evidence.is_empty() {
            write!(json, r#","evidence_ids":{}"#, ids_json(&item.evidence))
                .expect("writing to a String cannot fail");
        }
        if !supersedes.is_empty() {
            write!(json, r#","supersedes":{}"#, ids_json(&supersedes))
                .expect("writing to a String cannot fail");
        }
        json.push('}');
        Ok(json)
    };
    let section = |facts: bool| -> Result<String, ClaimError> {
        Ok(draft
            .statements
            .iter()
            .filter(|item| item.is_fact() == facts)
            .map(statement)
            .collect::<Result<Vec<_>, _>>()?
            .join(","))
    };
    let mut next = format!(
        r#"{{"classification":"recommendation","text":{}"#,
        json_string(&draft.next)
    );
    let next_supersedes = resolver.ids(&draft.next_supersedes)?;
    if !next_supersedes.is_empty() {
        write!(next, r#","supersedes":{}"#, ids_json(&next_supersedes))
            .expect("writing to a String cannot fail");
    }
    next.push('}');
    let mut body = format!(
        r#"{{"schema_version":1,"workspace_id":{},"task_id":{},"session_id":{},"snapshot_id":{},"objective":{},"verified_completed_work":[{}],"open_items":[{}],"next_action":{next}"#,
        json_string(&draft.workspace_id),
        json_string(&draft.task_id),
        json_string(&draft.session_id),
        json_string(draft.snapshot_id.as_deref().unwrap_or_default()),
        json_string(&draft.objective),
        section(true)?,
        section(false)?,
    );
    let mut withdrawals = resolver.ids(&draft.withdrawals)?;
    // U8 A5 (Owner O4): `--withdraw-session k` adds each statement in force
    // of `Session k`, once; the ledger records one `withdraws` edge for each.
    if let Some(number) = draft.withdraw_session {
        let claims = resolver.0.ok_or(ClaimError::NothingInForce(number))?;
        for id in claims.session_statements(number)? {
            if !withdrawals.contains(&id) {
                withdrawals.push(id);
            }
        }
    }
    // U9 K1 (U8 V-N3): `k` is valid; only now is the missing Snapshot told.
    if let Err(reason) = &draft.snapshot_id {
        return Err(ClaimError::SnapshotRequired(reason.to_string()));
    }
    if !withdrawals.is_empty() {
        write!(body, r#","withdrawals":{}"#, ids_json(&withdrawals))
            .expect("writing to a String cannot fail");
    }
    if let Some(reason) = &draft.withdrawal_reason {
        write!(body, r#","withdrawal_reason":{}"#, json_string(reason))
            .expect("writing to a String cannot fail");
    }
    body.push('}');
    Ok(body)
}

/// P4-C2 revision 7: a statement text longer than this many characters
/// gets a note on standard error from `checkpoint create`, twice what the
/// Pack keeps of a shortened body.
pub const LONG_STATEMENT_CHARS: usize = 2 * memprove_domain::PACK_BODY_KEPT;

/// P4-C2 revision 7: one note for each fact or open item of a
/// `createCheckpoint` body whose text is longer than
/// [`LONG_STATEMENT_CHARS`] Unicode scalar values, saying that the Context
/// Pack may show only its first 120. The next action is never shortened, so
/// it gets none. Notes only: nothing is refused and no exit code changes.
#[must_use]
pub fn long_statement_notes(body: &str) -> Vec<String> {
    let Ok(body) = parse_strict(body) else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    for (section, label) in [
        ("verified_completed_work", "fact"),
        ("open_items", "open item"),
    ] {
        let statements = body
            .get(section)
            .and_then(JsonValue::as_array)
            .unwrap_or_default();
        for (index, statement) in statements.iter().enumerate() {
            let length = statement
                .get("text")
                .and_then(JsonValue::as_str)
                .map_or(0, |text| text.chars().count());
            if length > LONG_STATEMENT_CHARS {
                notes.push(format!(
                    "the {label} at $.{section}[{index}] is {length} characters long; the \
                     Context Pack (`resume --pack`) may show only its first {} characters, so \
                     put its conclusion in the first sentence",
                    memprove_domain::PACK_BODY_KEPT
                ));
            }
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = "018f47a0-0000-7000-8000-000000000001";
    const D: &str = "018f47a0-0000-7000-8000-000000000002";

    fn capsule(status: &str) -> String {
        format!(
            r#"{{"status":"{status}","reasons":["object_missing"],"claims":[
                {{"number":1,"claim_id":"{C}/verified_completed_work/0","kind":"fact","text":"F1","standing":"active"}},
                {{"number":2,"claim_id":"{C}/open_items/0","kind":"open_item","text":"O1","standing":"active"}},
                {{"number":3,"claim_id":"decision/{D}","kind":"decision","text":"D1","standing":"active"}},
                {{"number":4,"claim_id":"{C}/verified_completed_work/1","kind":"fact","text":"F0","standing":"superseded"}},
                {{"number":5,"claim_id":"{C}/verified_completed_work/2","kind":"fact","text":"Fw","standing":"withdrawn"}}]}}"#
        )
    }

    /// P4-C2 revision 7: a fact or open item of 241 characters gets a
    /// note, one of 240 none; the next action never does.
    #[test]
    fn long_statements_get_a_note_about_the_pack() {
        let body = |fact: usize, open: usize, next: usize| {
            format!(
                r#"{{"verified_completed_work":[{{"text":"{}"}}],
                    "open_items":[{{"text":"short"}},{{"text":"{}"}}],
                    "next_action":{{"text":"{}"}}}}"#,
                "€".repeat(fact),
                "o".repeat(open),
                "n".repeat(next)
            )
        };
        assert!(long_statement_notes(&body(240, 240, 1_000)).is_empty());
        let notes = long_statement_notes(&body(241, 241, 1_000));
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(
            notes[0].starts_with("the fact at $.verified_completed_work[0] is 241 characters long"),
            "{}",
            notes[0]
        );
        assert!(notes[1].contains("$.open_items[1] is 241 characters"));
        assert!(notes[0].contains("may show only its first 120 characters"));
        assert!(long_statement_notes("not json").is_empty());
    }

    #[test]
    fn references_are_numbers_or_claim_ids() {
        assert_eq!(ClaimRef::parse("3", "--x"), Ok(ClaimRef::Number(3)));
        assert_eq!(ClaimRef::parse("#12", "--x"), Ok(ClaimRef::Number(12)));
        let id = format!("{C}/open_items/0");
        assert_eq!(ClaimRef::parse(&id, "--x"), Ok(ClaimRef::Id(id.clone())));
        let decision = format!("decision/{D}");
        assert_eq!(
            ClaimRef::parse(&decision, "--x"),
            Ok(ClaimRef::Id(decision.clone()))
        );
        for invalid in [
            "0",
            "#",
            "-1",
            "x",
            "3a",
            "decision/x",
            &format!("{C}/open_items/01"),
            &format!("{C}/decisions/0"),
            &format!("{}/open_items/0", C.to_uppercase()),
            &format!("{C}/open_items"),
        ] {
            assert!(ClaimRef::parse(invalid, "--x").is_err(), "{invalid}");
        }
    }

    fn draft() -> CheckpointDraft {
        CheckpointDraft {
            workspace_id: "W".to_owned(),
            task_id: "T".to_owned(),
            session_id: "S".to_owned(),
            snapshot_id: Ok("N".to_owned()),
            objective: "o".to_owned(),
            statements: vec![
                StatementDraft {
                    kind: StatementKind::Fact("F2".to_owned()),
                    evidence: vec!["E".to_owned()],
                    supersedes: vec![ClaimRef::Number(2)],
                },
                StatementDraft {
                    kind: StatementKind::Open("O2".to_owned()),
                    evidence: vec!["E".to_owned()],
                    supersedes: Vec::new(),
                },
                StatementDraft {
                    kind: StatementKind::Reaffirm(ClaimRef::Number(1)),
                    evidence: vec!["E".to_owned()],
                    supersedes: Vec::new(),
                },
            ],
            next: "n".to_owned(),
            next_supersedes: vec![ClaimRef::Id(format!("{C}/next_action/0"))],
            withdrawals: vec![ClaimRef::Number(3)],
            withdrawal_reason: Some("superseded by \"D2\"".to_owned()),
            withdraw_session: None,
            state_runs: Vec::new(),
            state_manifest: None,
            state_workspace: None,
        }
    }

    #[test]
    fn numbers_resolve_through_the_capsule_and_reaffirm_copies_the_fact() {
        let draft = Draft::Checkpoint(draft());
        assert!(draft.needs_capsule());
        let claims = CapsuleClaims::from_body(&capsule("stale")).unwrap();
        let body = draft.render(Some(&claims)).unwrap();
        let expected = format!(
            r#"{{"schema_version":1,"workspace_id":"W","task_id":"T","session_id":"S","snapshot_id":"N","objective":"o","verified_completed_work":[{{"classification":"verified_fact","text":"F2","evidence_ids":["E"],"supersedes":["{C}/open_items/0"]}},{{"classification":"verified_fact","text":"F1","evidence_ids":["E"],"supersedes":["{C}/verified_completed_work/0"]}}],"open_items":[{{"classification":"unknown","text":"O2","evidence_ids":["E"]}}],"next_action":{{"classification":"recommendation","text":"n","supersedes":["{C}/next_action/0"]}},"withdrawals":["decision/{D}"],"withdrawal_reason":"superseded by \"D2\""}}"#
        );
        assert_eq!(body, expected);
        assert!(parse_strict(&body).is_ok());
    }

    #[test]
    fn a_tampered_capsule_or_a_missing_number_resolves_nothing() {
        let refused = CapsuleClaims::from_body(&capsule("tampered"))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("tampered (object_missing)"), "{refused}");
        let claims = CapsuleClaims::from_body(&capsule("verified")).unwrap();
        let mut missing = draft();
        missing.withdrawals = vec![ClaimRef::Number(9)];
        let error = Draft::Checkpoint(missing)
            .render(Some(&claims))
            .unwrap_err()
            .to_string();
        assert!(error.contains("claim #9 is not in the Task Capsule, which lists #1 to #5"));
        let mut not_a_fact = draft();
        not_a_fact.statements[2].kind = StatementKind::Reaffirm(ClaimRef::Number(2));
        let error = Draft::Checkpoint(not_a_fact)
            .render(Some(&claims))
            .unwrap_err()
            .to_string();
        assert!(error.contains("only a fact can be reaffirmed"), "{error}");
        // P3-D2 (T13 N8): only an active fact can be reaffirmed.
        for (number, standing) in [(4, "superseded"), (5, "withdrawn")] {
            let mut inactive = draft();
            inactive.statements[2].kind = StatementKind::Reaffirm(ClaimRef::Number(number));
            let error = Draft::Checkpoint(inactive)
                .render(Some(&claims))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!(
                    "--reaffirm #{number} names a fact that is {standing}; only an active fact \
                     can be reaffirmed"
                )),
                "{error}"
            );
            assert!(error.contains("nothing was sent"), "{error}");
        }
        let mut by_id = draft();
        by_id.statements[2].kind =
            StatementKind::Reaffirm(ClaimRef::Id(format!("{C}/verified_completed_work/1")));
        assert!(
            Draft::Checkpoint(by_id)
                .render(Some(&claims))
                .unwrap_err()
                .to_string()
                .contains("is superseded")
        );
        assert!(Draft::Checkpoint(draft()).render(None).is_err());
    }

    /// P3-L L8: after `checkpoint create`, the numbers and kinds of the new
    /// statements, and which numbers each supersession, withdrawal, and
    /// reaffirmation touched, read from the Capsule after the write.
    #[test]
    fn l8_the_report_names_new_numbers_and_their_effects() {
        let n = "018f47a0-0000-7000-8000-000000000009";
        let claim = |number: u64, id: &str, kind: &str, by: &[(u64, &str)]| {
            let by = by
                .iter()
                .map(|(number, id)| format!(r#"{{"claim_id":"{id}","number":{number}}}"#))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"number":{number},"claim_id":"{id}","kind":"{kind}","text":"t","standing":"active","superseded_by":[{by}]}}"#
            )
        };
        let new_fact = format!("{n}/verified_completed_work/0");
        let reaffirm = format!("{n}/verified_completed_work/1");
        let new_open = format!("{n}/open_items/0");
        let new_next = format!("{n}/next_action/0");
        let capsule = format!(
            r#"{{"status":"stale","reasons":[],"claims":[{},{},{},{},{},{},{},{},{}]}}"#,
            claim(
                1,
                &format!("{C}/verified_completed_work/0"),
                "fact",
                &[(7, &reaffirm)]
            ),
            claim(
                2,
                &format!("{C}/open_items/0"),
                "open_item",
                &[(6, &new_fact)]
            ),
            claim(3, &format!("{C}/open_items/1"), "open_item", &[]),
            claim(
                4,
                &format!("{C}/next_action/0"),
                "next_action",
                &[(9, &new_next)]
            ),
            claim(5, &format!("decision/{D}"), "decision", &[]),
            claim(6, &new_fact, "fact", &[]),
            claim(7, &reaffirm, "fact", &[]),
            claim(8, &new_open, "open_item", &[]),
            claim(9, &new_next, "next_action", &[]),
        );
        let request = format!(
            r#"{{"verified_completed_work":[
                {{"classification":"verified_fact","text":"F2","supersedes":["{C}/open_items/0"]}},
                {{"classification":"verified_fact","text":"t","supersedes":["{C}/verified_completed_work/0"]}}],
               "open_items":[{{"classification":"unknown","text":"O"}}],
               "next_action":{{"classification":"recommendation","text":"n"}},
               "withdrawals":["{C}/open_items/1","decision/{D}"]}}"#
        );
        assert_eq!(
            checkpoint_report(&capsule, &request, n, &[false, true]).unwrap(),
            [
                "new statements: #6 fact, #7 fact, #8 open_item, #9 next_action",
                "superseded: #2 by #6, #4 by #9",
                "withdrawn: #3, #5",
                "reaffirmed: #1 as #7",
            ]
        );
        // Nothing touched: each effect says none.
        let bare = format!(
            r#"{{"status":"partial","reasons":[],"claims":[{}]}}"#,
            claim(1, &new_next, "next_action", &[])
        );
        assert_eq!(
            checkpoint_report(&bare, r#"{"next_action":{"text":"n"}}"#, n, &[]).unwrap(),
            [
                "new statements: #1 next_action",
                "superseded: none",
                "withdrawn: none",
                "reaffirmed: none",
            ]
        );
        assert!(checkpoint_report("not json", "{}", n, &[]).is_err());
    }

    #[test]
    fn claim_ids_alone_need_no_capsule() {
        let decision = Draft::Decision(DecisionDraft {
            task_id: "T".to_owned(),
            session_id: "S".to_owned(),
            content: "use \"JCS\"".to_owned(),
            rationale: Some("why".to_owned()),
            evidence: vec!["E".to_owned()],
            supersedes: vec![ClaimRef::Id(format!("decision/{D}"))],
        });
        assert!(!decision.needs_capsule());
        assert_eq!(
            decision.render(None).unwrap(),
            format!(
                r#"{{"schema_version":1,"task_id":"T","session_id":"S","content":"use \"JCS\"","rationale":"why","evidence_ids":["E"],"supersedes":["decision/{D}"]}}"#
            )
        );
        let bare = Draft::Decision(DecisionDraft {
            task_id: "T".to_owned(),
            session_id: "S".to_owned(),
            content: "c".to_owned(),
            rationale: None,
            evidence: Vec::new(),
            supersedes: vec![ClaimRef::Number(1)],
        });
        assert!(bare.needs_capsule());
        let claims = CapsuleClaims::from_body(&capsule("partial")).unwrap();
        assert_eq!(
            bare.render(Some(&claims)).unwrap(),
            format!(
                r#"{{"schema_version":1,"task_id":"T","session_id":"S","content":"c","supersedes":["{C}/verified_completed_work/0"]}}"#
            )
        );
    }
}
