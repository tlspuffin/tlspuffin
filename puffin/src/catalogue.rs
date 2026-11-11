//! Known vulnerabilities at run time: the witnesses of the catalogue entries
//! (`puffin-build/vendors/<vendor>/vulnerabilities.toml`), the state of each bundled PUT, and the
//! generic catalogue test that checks every witness on every PUT of a binary.
//!
//! A witness is a trace written in the DSL of a protocol crate that triggers one entry, registered
//! with `#[puffin::witness("<ID>")]`. The catalogue test runs each witness on each PUT of its
//! vendor that has the entry's capabilities, and checks the outcome against what the PUT's
//! catalogue state says:
//! - where the entry is the only active bug with a patch (`<preset>-only-<ID>`, or a preset fixing
//!   all the others), the witness must give an objective matching the entry's oracle (positive
//!   control);
//! - where the entry is patched and so is every other active bug with a patch (`<preset>-fix-all`),
//!   the witness must not give the entry's signature, and any objective must come from a bug that
//!   is still active (negative control);
//! - elsewhere the result is reported, and only warned about.
//!
//! An objective that matches another active entry's oracle is an overlap: the witness of X also
//! reaches Y. It is a warning, unless X declares `also_triggers = ["Y"]`.

use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub use puffin_build::catalogue::{
    Catalogue, Entry, LibraryState, Oracle, OracleKind, Status as EntryStatus,
};
use serde::Serialize;

use crate::agent::AgentName;
use crate::execution::Runner;
use crate::outcome::{execute_outcome, matches, Execution, Outcome, Signature};
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put::{PutDescriptor, PutOptions};
use crate::put_registry::{Factory, PutRegistry};
use crate::trace::{ConfigTrace, Spawner, Trace};

/// What a witness runs: earlier executions preparing the PUT state (in the same process), then the
/// trace that triggers the bug.
#[derive(Debug, Clone)]
pub struct WitnessRun<PT: ProtocolTypes> {
    pub prelude: Vec<Execution<PT>>,
    pub trace: Trace<PT>,
}

impl<PT: ProtocolTypes> WitnessRun<PT> {
    pub fn new(trace: Trace<PT>) -> Self {
        Self {
            prelude: vec![],
            trace,
        }
    }

    /// The executions of the witness, in order (the outcome is the last one's).
    pub fn executions(&self) -> Vec<Execution<PT>> {
        self.prelude
            .iter()
            .cloned()
            .chain(std::iter::once(Execution {
                trace: self.trace.clone(),
                config: ConfigTrace::default(),
            }))
            .collect()
    }
}

/// Functions that can be witnesses: seeds (`fn(AgentName) -> Trace`, `fn(AgentName, AgentName) ->
/// Trace`) and functions building a [`WitnessRun`] (`fn() -> WitnessRun`).
pub trait IntoWitnessRun<A, PT: ProtocolTypes> {
    fn into_witness_run(self) -> WitnessRun<PT>;
}

impl<PT: ProtocolTypes, F: Fn(AgentName) -> Trace<PT>> IntoWitnessRun<(AgentName,), PT> for F {
    fn into_witness_run(self) -> WitnessRun<PT> {
        WitnessRun::new(self(AgentName::first()))
    }
}

impl<PT: ProtocolTypes, F: Fn(AgentName, AgentName) -> Trace<PT>>
    IntoWitnessRun<(AgentName, AgentName), PT> for F
{
    fn into_witness_run(self) -> WitnessRun<PT> {
        let first = AgentName::first();
        WitnessRun::new(self(first, first.next()))
    }
}

impl<PT: ProtocolTypes, F: Fn() -> WitnessRun<PT>> IntoWitnessRun<(), PT> for F {
    fn into_witness_run(self) -> WitnessRun<PT> {
        self()
    }
}

/// The protocol of a witness function (`TypeId` of its protocol types).
pub fn protocol_of<A, PT: ProtocolTypes + 'static, F: IntoWitnessRun<A, PT>>(_: &F) -> TypeId {
    TypeId::of::<PT>()
}

/// A witness registered with `#[puffin::witness]` (type-erased: one registry for every protocol).
#[derive(Debug)]
pub struct WitnessRegistration {
    /// Id of the catalogue entry
    pub entry: &'static str,
    /// Name of the witness function
    pub name: &'static str,
    /// Module of the witness function
    pub module: &'static str,
    /// PUT capabilities the trace needs besides its entry's
    pub extra_capabilities: &'static [&'static str],
    pub protocol: fn() -> TypeId,
    /// Builds a `Box<WitnessRun<PT>>`
    pub build: fn() -> Box<dyn Any>,
}

#[linkme::distributed_slice]
pub static WITNESSES: [WitnessRegistration];

/// A witness of one protocol.
pub struct Witness<PT: ProtocolTypes> {
    pub entry: &'static str,
    pub name: &'static str,
    pub module: &'static str,
    pub extra_capabilities: &'static [&'static str],
    build: fn() -> Box<dyn Any>,
    _protocol: std::marker::PhantomData<fn() -> PT>,
}

impl<PT: ProtocolTypes + 'static> Witness<PT> {
    pub fn run(&self) -> WitnessRun<PT> {
        *(self.build)()
            .downcast::<WitnessRun<PT>>()
            .expect("witness of another protocol")
    }
}

/// The registered witnesses of a protocol, sorted by entry and name.
pub fn witnesses<PT: ProtocolTypes + 'static>() -> Vec<Witness<PT>> {
    let mut witnesses: Vec<Witness<PT>> = WITNESSES
        .iter()
        .filter(|w| (w.protocol)() == TypeId::of::<PT>())
        .map(|w| Witness {
            entry: w.entry,
            name: w.name,
            module: w.module,
            extra_capabilities: w.extra_capabilities,
            build: w.build,
            _protocol: std::marker::PhantomData,
        })
        .collect();
    witnesses.sort_by_key(|w| (w.entry, w.name));
    witnesses
}

/// What a bundled PUT knows about the catalogue (see [`Factory::catalogue`]).
#[derive(Debug, Clone)]
pub struct PutCatalogue {
    /// The state of every catalogue entry in the PUT's library (`Err`: the library was built
    /// without catalogue state, or with an unreadable one)
    pub state: Result<LibraryState, String>,
    /// Instrumentation of the library (e.g. "asan", "sancov")
    pub instrumentation: Vec<String>,
}

impl PutCatalogue {
    pub fn from_bundle(state: Option<&str>, instrumentation: &[&str]) -> Self {
        Self {
            state: state
                .ok_or_else(|| {
                    "built without catalogue state (rebuild the vendor library with mk_vendor)"
                        .to_string()
                })
                .and_then(LibraryState::from_toml),
            instrumentation: instrumentation.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn has_asan(&self) -> bool {
        self.instrumentation.iter().any(|i| i == "asan")
    }
}

/// The catalogues of `vendors`, as in the source tree the binary was built from.
pub fn load_catalogues(vendors: &[&str]) -> Result<BTreeMap<String, Catalogue>, String> {
    vendors
        .iter()
        .map(|v| {
            Catalogue::load(v)
                .map(|c| (v.to_string(), c))
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// The vendors whose C harness is in `<protocol>puffin/harness/` (e.g. "tls": wolfssl, openssl,
/// ...).
pub fn vendors_with_harness(protocol: &str) -> Vec<String> {
    puffin_build::catalogue::vendors()
        .into_iter()
        .filter(|vendor| {
            puffin_build::puffin::project_dir()
                .join(format!("{protocol}puffin/harness/{vendor}"))
                .is_dir()
        })
        .collect()
}

/// The two-way check of witnesses and entries: every entry of `catalogues` has a witness or says
/// why not (`no_witness`), every witness names an existing entry. Returns the problems found.
pub fn check_witnesses<PT: ProtocolTypes + 'static>(
    catalogues: &BTreeMap<String, Catalogue>,
    witnesses: &[Witness<PT>],
) -> Vec<String> {
    let mut problems = vec![];

    for (vendor, catalogue) in catalogues {
        for (id, entry) in &catalogue.entries {
            let count = witnesses.iter().filter(|w| w.entry == id).count();
            match (&entry.no_witness, count) {
                (None, 0) => problems.push(format!(
                    "{vendor}: {id} has no witness: annotate the trace that triggers it with \
                     #[puffin::witness(\"{id}\")], or give the entry no_witness = \"<reason>\""
                )),
                (Some(_), n) if n > 0 => problems.push(format!(
                    "{vendor}: {id} says no_witness but has {n} witness(es): remove no_witness"
                )),
                _ => (),
            }
        }
    }

    for witness in witnesses {
        if !catalogues
            .values()
            .any(|c| c.entries.contains_key(witness.entry))
        {
            problems.push(format!(
                "witness {}::{} names '{}', which is not an entry of the catalogues of {}",
                witness.module,
                witness.name,
                witness.entry,
                catalogues.keys().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }

    problems
}

/// The role of a PUT for an entry in the catalogue matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// The entry is active and is the only active bug with a patch: the witness must trigger it
    Positive,
    /// The entry and every other active bug with a patch are patched: the witness must not trigger
    /// it
    Negative,
    /// Any other PUT: the result is reported, never fails
    Other,
}

/// The expectation of one witness on one PUT.
#[derive(Debug, Clone, Serialize)]
pub struct Case {
    pub entry: String,
    pub witness: String,
    pub put: String,
    pub role: Role,
    /// Status of the entry in the PUT
    pub status: String,
}

/// The result of one case on real executions.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    #[serde(flatten)]
    pub case: Case,
    /// "pass", "fail", "warning", "skipped"
    pub verdict: &'static str,
    pub message: String,
    pub outcomes: Vec<Outcome>,
    /// Active entries the objective's signature matches, other than the witness's own
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub overlaps: Vec<String>,
}

/// How many times a witness runs on a PUT (a positive control passes when one run triggers the bug,
/// a negative one fails when one run does).
pub const RUNS: usize = 3;
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The cases of the catalogue matrix on the PUTs of `registry`: one per (witness, PUT of the
/// entry's vendor with the capabilities). PUTs without catalogue state give no case (see
/// [`state_problems`]).
pub fn cases<PB: ProtocolBehavior>(
    registry: &PutRegistry<PB>,
    catalogues: &BTreeMap<String, Catalogue>,
    witnesses: &[Witness<PB::ProtocolTypes>],
) -> Vec<(Case, Result<(), String>)>
where
    PB::ProtocolTypes: 'static,
{
    let mut cases = vec![];
    let mut puts: Vec<(&str, &dyn Factory<PB>)> = registry.puts().collect();
    puts.sort_by_key(|(name, _)| *name);

    for witness in witnesses {
        let Some((_, catalogue)) = catalogues
            .iter()
            .find(|(_, c)| c.entries.contains_key(witness.entry))
        else {
            continue;
        };
        let entry = &catalogue.entries[witness.entry];

        for (name, factory) in &puts {
            let Some(put) = factory.catalogue() else {
                continue;
            };
            let Ok(state) = &put.state else { continue };
            if state.vendor != catalogue.vendor {
                continue;
            }

            let missing: Vec<&str> = entry
                .capabilities
                .iter()
                .map(String::as_str)
                .chain(witness.extra_capabilities.iter().copied())
                .filter(|c| !factory.supports(c))
                .collect();
            if !missing.is_empty() {
                continue;
            }

            let status = state
                .status(witness.entry)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".into());
            // where the witness is known not to reach the bug, nothing is decided from its outcome
            let role = if entry.witness_reaches(&state.version) {
                role(state, witness.entry)
            } else {
                Role::Other
            };
            let case = Case {
                entry: witness.entry.into(),
                witness: witness.name.into(),
                put: name.to_string(),
                role,
                status,
            };

            let runnable = if entry.oracle.as_ref().is_some_and(|o| o.asan.is_some())
                && !put.has_asan()
            {
                Err(
                    "the oracle needs AddressSanitizer, which this PUT is built without"
                        .to_string(),
                )
            } else if state.entries.get(witness.entry).map(|e| e.hash.as_str())
                != catalogue.build_hash(witness.entry)
            {
                Err(format!(
                    "the PUT was built with another version of {} (affected versions, options or patches): rebuild it",
                    witness.entry
                ))
            } else {
                Ok(())
            };
            cases.push((case, runnable));
        }
    }
    cases
}

/// The role of a PUT for entry `id`, from the PUT's catalogue state.
pub fn role(state: &LibraryState, id: &str) -> Role {
    let others_with_patch_fixed = state
        .entries
        .iter()
        .all(|(other, e)| other == id || e.state != EntryStatus::Active || !state.patchable(other));
    match state.status(id) {
        Some(EntryStatus::Active) if others_with_patch_fixed => Role::Positive,
        Some(EntryStatus::Fixed) if others_with_patch_fixed => Role::Negative,
        _ => Role::Other,
    }
}

/// Problems with the catalogue state of the PUTs of a binary (missing state, state of another
/// catalogue revision).
pub fn state_problems<PB: ProtocolBehavior>(
    registry: &PutRegistry<PB>,
    catalogues: &BTreeMap<String, Catalogue>,
) -> Vec<String> {
    let mut problems = vec![];
    for (name, factory) in registry.puts() {
        let Some(put) = factory.catalogue() else {
            continue;
        };
        match &put.state {
            Err(e) => problems.push(format!("PUT {name}: {e}")),
            Ok(state) => {
                if !catalogues.contains_key(&state.vendor) {
                    problems.push(format!(
                        "PUT {name}: vendor '{}' has no catalogue in this tree",
                        state.vendor
                    ));
                } else if let Some(catalogue) = catalogues.get(&state.vendor) {
                    let stale: Vec<&str> = catalogue
                        .entries
                        .keys()
                        .filter(|id| {
                            state.entries.get(*id).map(|e| e.hash.as_str())
                                != catalogue.build_hash(id)
                        })
                        .map(String::as_str)
                        .collect();
                    if !stale.is_empty() {
                        problems.push(format!(
                            "PUT {name}: built with another version of {} (affected versions, options or patches: rebuild it with mk_vendor)",
                            stale.join(", ")
                        ));
                    }
                }
            }
        }
    }
    problems
}

/// Run one case: the witness `runs` times on its PUT (with the entry's PUT options), then judge the
/// outcomes.
pub fn run_case<PB: ProtocolBehavior>(
    registry: &PutRegistry<PB>,
    catalogues: &BTreeMap<String, Catalogue>,
    witness: &Witness<PB::ProtocolTypes>,
    case: &Case,
    runs: usize,
) -> CaseResult
where
    PB::ProtocolTypes: 'static,
{
    let catalogue = catalogues
        .values()
        .find(|c| c.entries.contains_key(witness.entry))
        .expect("case of an unknown entry");
    let entry = &catalogue.entries[witness.entry];
    let factory = registry
        .find_by_id(&case.put)
        .expect("case of an unknown PUT");
    let put = factory
        .catalogue()
        .expect("case of a PUT outside the catalogue");
    let state = put.state.as_ref().expect("case of a PUT without state");

    let options: Vec<(&str, &str)> = entry
        .put_options
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut registry = registry.clone();
    if let Err(e) = registry.set_default(PutDescriptor::new(
        case.put.clone(),
        PutOptions::from(options),
    )) {
        return result(case, "fail", e, vec![], vec![]);
    }
    let runner = Runner::new(registry.clone(), Spawner::new(registry));
    let executions = witness.run().executions();

    let mut outcomes = vec![];
    for _ in 0..runs {
        match execute_outcome(&runner, &executions, TIMEOUT) {
            Ok(report) => {
                let triggered = report.outcome.signature().is_some_and(|s| {
                    entry
                        .oracle
                        .as_ref()
                        .is_some_and(|o| matches(o, &s, put.has_asan()))
                });
                outcomes.push(report.outcome);
                // a positive control needs one trigger, a negative one fails on the first
                if triggered {
                    break;
                }
            }
            Err(e) => outcomes.push(Outcome::Error {
                message: e.to_string(),
            }),
        }
    }

    judge(case, entry, catalogue, state, put.has_asan(), outcomes)
}

fn result(
    case: &Case,
    verdict: &'static str,
    message: String,
    outcomes: Vec<Outcome>,
    overlaps: Vec<String>,
) -> CaseResult {
    CaseResult {
        case: case.clone(),
        verdict,
        message,
        outcomes,
        overlaps,
    }
}

/// The active entries (other than `id`) whose oracle the signature matches.
fn explained_by(
    catalogue: &Catalogue,
    state: &LibraryState,
    id: &str,
    signature: &Signature,
    asan: bool,
) -> Vec<String> {
    catalogue
        .entries
        .iter()
        .filter(|(other, _)| *other != id && state.status(other) == Some(EntryStatus::Active))
        .filter(|(_, e)| {
            e.oracle
                .as_ref()
                .is_some_and(|o| matches(o, signature, asan))
        })
        .map(|(other, _)| other.clone())
        .collect()
}

/// Judge the outcomes of a witness on a PUT.
pub fn judge(
    case: &Case,
    entry: &Entry,
    catalogue: &Catalogue,
    state: &LibraryState,
    asan: bool,
    outcomes: Vec<Outcome>,
) -> CaseResult {
    let id = case.entry.as_str();
    let Some(oracle) = &entry.oracle else {
        return result(
            case,
            "fail",
            format!("{id} has a witness but no oracle"),
            outcomes,
            vec![],
        );
    };
    let active = state.status(id) == Some(EntryStatus::Active);

    let own = outcomes
        .iter()
        .find(|o| o.signature().is_some_and(|s| matches(oracle, &s, asan)));
    let objective = outcomes.iter().find(|o| o.is_objective());
    let overlaps: Vec<String> = objective
        .and_then(|o| o.signature())
        .map(|s| explained_by(catalogue, state, id, &s, asan))
        .unwrap_or_default();
    let declared = |others: &[String]| others.iter().all(|o| entry.also_triggers.contains(o));
    let describe = |o: Option<&Outcome>| {
        o.map(|o| o.to_string())
            .or_else(|| outcomes.last().map(|o| o.to_string()))
            .unwrap_or_else(|| "no execution".into())
    };

    match case.role {
        Role::Positive => match (own, objective) {
            (Some(o), _) => result(case, "pass", format!("triggers {id}: {o}"), outcomes.clone(), vec![]),
            (None, Some(o)) => result(
                case,
                "fail",
                format!(
                    "{id} is the only active bug with a patch here, but its witness gives {o}, not its oracle \
                     ({oracle}){}",
                    if overlaps.is_empty() {
                        String::new()
                    } else {
                        format!("; it matches {}", overlaps.join(", "))
                    }
                ),
                outcomes.clone(),
                overlaps,
            ),
            (None, None) => result(
                case,
                "fail",
                format!(
                    "{id} is the only active bug with a patch here, but its witness does not trigger it ({})",
                    describe(None)
                ),
                outcomes.clone(),
                vec![],
            ),
        },
        Role::Negative => match (own, objective) {
            (Some(o), _) if overlaps.is_empty() => result(
                case,
                "fail",
                format!("{id} is patched here, but its witness still gives its signature: {o}"),
                outcomes.clone(),
                vec![],
            ),
            (_, Some(o)) if overlaps.is_empty() => result(
                case,
                "fail",
                format!(
                    "every bug with a patch is patched here, and the witness of {id} gives {o}, which no active \
                     entry explains (an incomplete patch, or a bug missing from the catalogue)"
                ),
                outcomes.clone(),
                vec![],
            ),
            (_, Some(o)) if declared(&overlaps) => result(
                case,
                "pass",
                format!("gives {o}: {} (declared in also_triggers)", overlaps.join(", ")),
                outcomes.clone(),
                overlaps,
            ),
            (_, Some(o)) => result(
                case,
                "warning",
                format!(
                    "overlap: the witness of {id} also triggers {} ({o})",
                    overlaps.join(", ")
                ),
                outcomes.clone(),
                overlaps,
            ),
            (_, None) => result(case, "pass", format!("{id} patched: {}", describe(None)), outcomes.clone(), vec![]),
        },
        Role::Other => match objective {
            // the witness triggers its own bug where the bug is: as expected
            Some(_) if own.is_some() && active => result(case, "pass", describe(own), outcomes.clone(), vec![]),
            Some(o) if !overlaps.is_empty() && declared(&overlaps) => {
                result(case, "pass", format!("gives {o}: {}", overlaps.join(", ")), outcomes.clone(), overlaps)
            }
            Some(o) if !overlaps.is_empty() => result(
                case,
                "warning",
                format!(
                    "overlap: the witness of {id} also triggers {} ({o})",
                    overlaps.join(", ")
                ),
                outcomes.clone(),
                overlaps,
            ),
            Some(o) => result(
                case,
                "warning",
                format!(
                    "{id} is {} here, and its witness gives {o}, which no active entry explains (check the \
                     affected range)",
                    case.status
                ),
                outcomes.clone(),
                vec![],
            ),
            None if active && !entry.witness_reaches(&state.version) => result(
                case,
                "pass",
                format!(
                    "{id} is active here, but its witness only reaches it on {} ({})",
                    entry.witness_versions.as_ref().map(|r| r.as_str()).unwrap_or("-"),
                    describe(None)
                ),
                outcomes.clone(),
                vec![],
            ),
            None if active => result(
                case,
                "warning",
                format!("{id} is active here, but its witness does not trigger it ({})", describe(None)),
                outcomes.clone(),
                vec![],
            ),
            None => result(case, "pass", describe(None), outcomes.clone(), vec![]),
        },
    }
}

impl fmt::Display for CaseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} on {} ({:?}, {}): {}",
            self.case.entry,
            self.case.witness,
            self.case.put,
            self.case.role,
            self.case.status,
            self.message
        )
    }
}

/// The report of a catalogue check, written as JSON to `$PUFFIN_CATALOGUE_REPORT` when set.
#[derive(Debug, Serialize)]
pub struct Report {
    pub problems: Vec<String>,
    pub results: Vec<CaseResult>,
    pub skipped: Vec<(Case, String)>,
}

impl Report {
    pub fn warnings(&self) -> impl Iterator<Item = &CaseResult> {
        self.results.iter().filter(|r| r.verdict == "warning")
    }

    pub fn failures(&self) -> impl Iterator<Item = &CaseResult> {
        self.results.iter().filter(|r| r.verdict == "fail")
    }

    /// The matrix of results, one line per witness, one column per PUT.
    pub fn matrix(&self) -> String {
        let mut puts: Vec<&str> = self.results.iter().map(|r| r.case.put.as_str()).collect();
        puts.extend(self.skipped.iter().map(|(c, _)| c.put.as_str()));
        puts.sort();
        puts.dedup();
        let mut rows: BTreeMap<(String, String), BTreeMap<&str, &str>> = BTreeMap::new();
        for r in &self.results {
            let mark = match (r.verdict, r.case.role) {
                ("fail", _) => "FAIL",
                ("warning", _) if !r.overlaps.is_empty() => "OVERLAP",
                ("warning", _) => "warn",
                (_, _) if r.outcomes.iter().any(|o| o.is_objective()) => "triggers",
                _ => "-",
            };
            rows.entry((r.case.entry.clone(), r.case.witness.clone()))
                .or_default()
                .insert(&r.case.put, mark);
        }
        for (c, _) in &self.skipped {
            rows.entry((c.entry.clone(), c.witness.clone()))
                .or_default()
                .insert(&c.put, "skipped");
        }
        let mut out = String::new();
        for put in &puts {
            out.push_str(&format!("  {put}\n"));
        }
        for ((entry, witness), cells) in rows {
            out.push_str(&format!("{entry} {witness}:"));
            for put in &puts {
                out.push_str(&format!(" {}", cells.get(put).copied().unwrap_or("")));
            }
            out.push('\n');
        }
        out
    }
}

/// The vendors of the PUTs of `registry` that carry a catalogue state.
pub fn bundled_vendors<PB: ProtocolBehavior>(registry: &PutRegistry<PB>) -> Vec<String> {
    let mut vendors: Vec<String> = registry
        .puts()
        .filter_map(|(_, f)| f.catalogue())
        .filter_map(|c| c.state.ok().map(|s| s.vendor))
        .collect();
    vendors.sort();
    vendors.dedup();
    vendors
}

/// The catalogue check of the PUTs of `registry` (what the catalogue test does, in sequence): the
/// two-way check of witnesses and entries, the catalogue state of each PUT, and every case.
pub fn check<PB: ProtocolBehavior>(
    registry: &PutRegistry<PB>,
    vendors: &[&str],
) -> Result<Report, String>
where
    PB::ProtocolTypes: 'static,
{
    let catalogues = load_catalogues(vendors)?;
    let witnesses = witnesses::<PB::ProtocolTypes>();
    let mut report = Report {
        problems: check_witnesses(&catalogues, &witnesses),
        results: vec![],
        skipped: vec![],
    };
    report
        .problems
        .extend(state_problems(registry, &catalogues));
    for (case, runnable) in cases(registry, &catalogues, &witnesses) {
        match runnable {
            Err(reason) => report.skipped.push((case, reason)),
            Ok(()) => {
                let witness = witnesses
                    .iter()
                    .find(|w| w.entry == case.entry && w.name == case.witness)
                    .expect("case of an unknown witness");
                report
                    .results
                    .push(run_case(registry, &catalogues, witness, &case, RUNS));
            }
        }
    }
    Ok(report)
}

/// The state of one PUT, as listed by `catalogue --json`.
#[derive(Debug, Serialize)]
pub struct PutListing {
    pub put: String,
    pub instrumentation: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<LibraryState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One witness, as listed by `catalogue --json`.
#[derive(Debug, Serialize)]
pub struct WitnessListing {
    pub entry: String,
    pub name: String,
    pub module: String,
    pub extra_capabilities: Vec<String>,
}

/// What a binary knows about the catalogue: its PUTs' states and its witnesses.
pub fn listing<PB: ProtocolBehavior>(
    registry: &PutRegistry<PB>,
) -> (Vec<PutListing>, Vec<WitnessListing>)
where
    PB::ProtocolTypes: 'static,
{
    let mut puts: Vec<PutListing> = registry
        .puts()
        .filter_map(|(name, f)| f.catalogue().map(|c| (name.to_string(), c)))
        .map(|(put, c)| PutListing {
            put,
            instrumentation: c.instrumentation,
            error: c.state.as_ref().err().cloned(),
            state: c.state.ok(),
        })
        .collect();
    puts.sort_by(|a, b| a.put.cmp(&b.put));
    let witnesses = witnesses::<PB::ProtocolTypes>()
        .iter()
        .map(|w| WitnessListing {
            entry: w.entry.into(),
            name: w.name.into(),
            module: w.module.into(),
            extra_capabilities: w.extra_capabilities.iter().map(|s| s.to_string()).collect(),
        })
        .collect();
    (puts, witnesses)
}

/// The generic catalogue test of a protocol crate (a test target with `harness = false`):
///
/// ```ignore
/// fn main() -> std::process::ExitCode {
///     puffin::catalogue::test_main(tlspuffin::put_registry::tls_registry, &["wolfssl", "openssl"])
/// }
/// ```
///
/// One test checks the witnesses against the catalogues (it needs no PUT), one per PUT checks its
/// catalogue state, and one per (witness, PUT) runs the witness ([`cases`]). The usual test
/// arguments apply (filter, `--list`, ...).
pub fn test_main<PB: ProtocolBehavior + 'static>(
    registry: fn() -> PutRegistry<PB>,
    vendors: &[&str],
) -> std::process::ExitCode
where
    PB::ProtocolTypes: 'static,
{
    use std::sync::{Arc, Mutex};

    use libtest_mimic::{Arguments, Failed, Trial};

    let mut args = Arguments::from_args();
    // one test at a time unless asked otherwise: each test forks, and forking a process whose other
    // threads hold locks (allocator, logger) can deadlock the child
    if args.test_threads.is_none() {
        args.test_threads = Some(1);
    }
    let catalogues = match load_catalogues(vendors) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let witnesses = Arc::new(witnesses::<PB::ProtocolTypes>());
    let report = Arc::new(Mutex::new(Report {
        problems: vec![],
        results: vec![],
        skipped: vec![],
    }));

    let mut trials = vec![];

    {
        let catalogues = catalogues.clone();
        let witnesses = witnesses.clone();
        let report = report.clone();
        trials.push(Trial::test("catalogue::witnesses", move || {
            let problems = check_witnesses(&catalogues, &witnesses);
            report.lock().unwrap().problems.extend(problems.clone());
            if problems.is_empty() {
                Ok(())
            } else {
                Err(Failed::from(problems.join("\n")))
            }
        }));
    }

    {
        let catalogues = catalogues.clone();
        let report = report.clone();
        trials.push(Trial::test("catalogue::put_states", move || {
            let problems = state_problems(&registry(), &catalogues);
            report.lock().unwrap().problems.extend(problems.clone());
            if problems.is_empty() {
                Ok(())
            } else {
                Err(Failed::from(problems.join("\n")))
            }
        }));
    }

    for (case, runnable) in cases(&registry(), &catalogues, &witnesses) {
        let name = format!("{}::{}::{}", case.entry, case.witness, case.put);
        let catalogues = catalogues.clone();
        let witnesses = witnesses.clone();
        let report = report.clone();
        let trial = Trial::test(name, move || {
            if let Err(reason) = runnable {
                let fail = reason.contains("rebuild");
                report
                    .lock()
                    .unwrap()
                    .skipped
                    .push((case.clone(), reason.clone()));
                return if fail {
                    Err(Failed::from(reason))
                } else {
                    Ok(())
                };
            }
            let witness = witnesses
                .iter()
                .find(|w| w.entry == case.entry && w.name == case.witness)
                .expect("case of an unknown witness");
            let result = run_case(&registry(), &catalogues, witness, &case, RUNS);
            if result.verdict == "warning" {
                eprintln!("warning: {result}");
            }
            let failed = result.verdict == "fail";
            let message = result.to_string();
            report.lock().unwrap().results.push(result);
            if failed {
                Err(Failed::from(message))
            } else {
                Ok(())
            }
        });
        trials.push(trial);
    }

    let conclusion = libtest_mimic::run(&args, trials);

    let report = report.lock().unwrap();
    if !report.results.is_empty() || !report.skipped.is_empty() {
        eprintln!("\ncatalogue matrix:\n{}", report.matrix());
    }
    for warning in report.warnings() {
        eprintln!("warning: {warning}");
    }
    if let Ok(path) = std::env::var("PUFFIN_CATALOGUE_REPORT") {
        if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&*report).unwrap()) {
            eprintln!("cannot write the catalogue report to {path}: {e}");
        }
    }

    conclusion.exit_code()
}
