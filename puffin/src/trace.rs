//! This module define the execution [`Trace`]s.
//!
//! Each [`Trace`]s consist of several [`Step`]s, of which each has either an [`OutputAction`] or
//! [`InputAction`]. This is a declarative way of modeling communication between [`Agent`]s. The
//! [`TraceContext`] holds data, also known as [`Knowledge`], which is created by [`Agent`]s
//! during the concrete execution of the Trace. It also holds the [`Agent`]s with the references to
//! concrete PUT.
//!
//! ### Serializability of Traces
//!
//! Each trace is serializable to JSON or even binary data. This helps at reproducing discovered
//! security vulnerabilities during fuzzing. If a trace triggers a security vulnerability we can
//! store it on disk and replay it when investigating the case.
//! As traces depend on concrete implementations as discussed in the next section we need to link
//! serialized data like strings or numerical IDs to functions implemented in Rust.

use core::fmt;
use std::any::TypeId;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::mem;
use std::vec::IntoIter;

use clap::error::Result;
use comparable::Comparable;
use serde::{Deserialize, Serialize, Serializer};

use crate::agent::{Agent, AgentDescriptor, AgentName};
use crate::algebra::bitstrings::Payloads;
use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::{remove_prefix, Matcher, Term, TermType};
use crate::claims::{Claim, GlobalClaimList, SecurityViolationPolicy};
use crate::differential::TraceDifference;
use crate::error::Error;
use crate::fuzzer::stats_stage::{
    ALL_EXEC, ALL_EXEC_AGENT_SUCCESS, ALL_EXEC_SUCCESS, ERROR_AGENT, ERROR_CODEC, ERROR_EXTRACTION,
    ERROR_FN, ERROR_IO, ERROR_PUT, ERROR_STREAM, ERROR_TERM, ERROR_TERMBUG,
};
use crate::protocol::{EvaluatedTerm, ProtocolBehavior, ProtocolTypes};
use crate::put::PutDescriptor;
use crate::put_registry::PutRegistry;
use crate::stream::Stream;
use crate::trace::Action::Input;

#[derive(Debug, Deserialize, Serialize, Clone, Hash, Eq, PartialEq)]
pub struct Query<M> {
    pub source: Option<Source>,
    pub matcher: Option<M>,
    pub counter: u16, // in case an agent sends multiple messages of the same type
}

impl<M: Matcher> fmt::Display for Query<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({:?}, {})[{:?}]",
            self.source, self.counter, self.matcher
        )
    }
}

/// [Source] stores the origin of a knowledge, whether the agent name or
/// the label of the precomputation that produced it
#[derive(Debug, PartialEq, Eq, Clone, Hash, Deserialize, Serialize)]
pub enum Source {
    Agent(AgentName),
    Label(Option<String>),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Agent(x) => write!(f, "agent:{x}"),
            Self::Label(x) => write!(f, "label:{x:?}"),
        }
    }
}

/// [Knowledge] describes an atomic piece of knowledge inferred by the
/// [`crate::protocol::Extractable::extract_knowledge`] function
/// [Knowledge] is made of the data, the source of the output, the
/// TLS message type and the internal type.
#[derive(Debug)]
pub struct Knowledge<'a, PT: ProtocolTypes> {
    pub source: &'a Source,
    pub matcher: Option<PT::Matcher>,
    pub data: &'a dyn EvaluatedTerm<PT>,
}

/// [`RawKnowledge`] stores
#[derive(Debug)]
pub struct RawKnowledge<PT: ProtocolTypes> {
    pub source: Source,
    /// the step of the trace that produced this knowledge
    pub step: Option<StepNumber>,
    pub matcher: Option<PT::Matcher>,
    pub associated_term: Option<Term<PT>>,
    pub data: Box<dyn EvaluatedTerm<PT>>,
}

impl<PT: ProtocolTypes> fmt::Display for RawKnowledge<PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

impl<'a, PT: ProtocolTypes> IntoIterator for &'a RawKnowledge<PT> {
    type IntoIter = IntoIter<Knowledge<'a, PT>>;
    type Item = Knowledge<'a, PT>;

    fn into_iter(self) -> Self::IntoIter {
        let mut knowledges = vec![];
        let _ = self
            .data
            .extract_knowledge(&mut knowledges, self.matcher.clone(), &self.source);
        knowledges.into_iter()
    }
}

impl<PT: ProtocolTypes> Knowledge<'_, PT> {
    pub fn specificity(&self) -> u32 {
        self.matcher.specificity()
    }
}

impl<PT: ProtocolTypes> Knowledge<'_, PT> {
    pub fn debug_print<PB>(&self, ctx: &TraceContext<PB>, source: &Source)
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        let data_type_id = self.data.type_id();
        log::debug!(
            "New knowledge {}: {}  (counter: {})",
            &self,
            remove_prefix(self.data.type_name()),
            ctx.number_matching_message_with_source(source.clone(), data_type_id, &self.matcher)
        );
        log::debug!("Knowledge data: {:?}", self.data);
    }
}

impl<PT: ProtocolTypes> fmt::Display for Knowledge<'_, PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

#[derive(Debug, Default)]
pub struct KnowledgeStore<PT: ProtocolTypes> {
    raw_knowledge: Vec<RawKnowledge<PT>>,
}

impl<PT: ProtocolTypes> KnowledgeStore<PT> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            raw_knowledge: vec![],
        }
    }

    pub fn add_raw_knowledge<T: EvaluatedTerm<PT> + 'static>(
        &mut self,
        data: T,
        step: Option<StepNumber>,
        source: Source,
        term: Option<Term<PT>>,
    ) {
        log::trace!("Adding raw knowledge for {:?}", &data);

        self.raw_knowledge.push(RawKnowledge {
            source,
            matcher: None,
            data: Box::new(data),
            associated_term: term,
            step,
        });
    }

    pub fn add_raw_boxed_knowledge(
        &mut self,
        data: Box<dyn EvaluatedTerm<PT>>,
        step: Option<StepNumber>,
        source: Source,
        term: Option<Term<PT>>,
    ) {
        log::trace!("Adding raw knowledge : {:?}", &data);

        self.raw_knowledge.push(RawKnowledge {
            source,
            matcher: None,
            data,
            associated_term: term,
            step,
        });
    }

    pub fn number_matching_message_with_source(
        &self,
        source: Source,
        type_id: TypeId,
        tls_message_type: &Option<PT::Matcher>,
    ) -> usize {
        self.raw_knowledge
            .iter()
            .filter(|raw| raw.source == source)
            .flatten()
            .filter(|knowledge| {
                knowledge.matcher == *tls_message_type && knowledge.data.type_id() == type_id
            })
            .count()
    }

    /// Count the number of sub-messages of type `type_id` in the output message.
    pub fn number_matching_message(
        &self,
        type_id: TypeId,
        tls_message_type: &Option<PT::Matcher>,
    ) -> usize {
        self.raw_knowledge
            .iter()
            .flatten()
            .filter(|knowledge| {
                knowledge.matcher == *tls_message_type && knowledge.data.type_id() == type_id
            })
            .count()
    }

    /// Returns the variable which matches best -> highest specificity
    /// If we want a variable with lower specificity, then we can just query less specific
    pub fn find_variable(
        &self,
        query_type_shape: TypeShape<PT>,
        query: &Query<PT::Matcher>,
    ) -> Option<&(dyn EvaluatedTerm<PT>)> {
        log::trace!(
            "Looking for variable {:?} with query_type_shape {:?} and query {:?}",
            self,
            query_type_shape,
            query
        );
        let query_type_id: TypeId = query_type_shape.into();

        let mut possibilities: Vec<Knowledge<PT>> = self
            .raw_knowledge
            .iter()
            .filter(|raw| (query.source.is_none() || query.source.as_ref().unwrap() == &raw.source))
            .flatten()
            .filter(|knowledge| {
                query_type_id == knowledge.data.type_id()
                    && knowledge.matcher.matches(&query.matcher)
            })
            .collect();

        possibilities.sort_by_key(Knowledge::specificity);

        possibilities
            .get(query.counter as usize)
            .map(|possibility| possibility.data)
    }

    pub fn knowledges(&self) -> &Vec<RawKnowledge<PT>> {
        &self.raw_knowledge
    }

    pub fn compare(&self, other: &Self) -> Result<(), Vec<TraceDifference>> {
        let whitelist = PT::differential_fuzzing_whitelist();
        let blacklist = PT::differential_fuzzing_blacklist();

        let mut differences: Vec<TraceDifference> = vec![];

        let mut first_store: Vec<Knowledge<'_, PT>> = self
            .knowledges()
            .iter()
            .flatten()
            .filter(|x| filter_knowledge(x, &whitelist, &blacklist))
            .collect();
        let mut second_store: Vec<Knowledge<'_, PT>> = other
            .knowledges()
            .iter()
            .flatten()
            .filter(|x| filter_knowledge(x, &whitelist, &blacklist))
            .collect();
        let first_store_count = first_store.len();
        let second_store_count = second_store.len();

        if first_store_count > second_store_count {
            second_store.extend((second_store_count..first_store_count).map(|_| Knowledge {
                source: &Source::Label(None),
                matcher: None,
                data: &(),
            }))
        } else {
            first_store.extend((first_store_count..second_store_count).map(|_| Knowledge {
                source: &Source::Label(None),
                matcher: None,
                data: &(),
            }))
        }

        log::trace!("Comparing knowledge stores");
        let _ = std::iter::zip(first_store, second_store)
            .enumerate()
            .map(|(idx, (x, y))| {
                log::trace!(
                    "{} (source:{}) | {} (source:{})",
                    x.data.type_name(),
                    x.source,
                    y.data.type_name(),
                    y.source
                );
                x.data.find_differences(y.data, &mut differences, idx);
            })
            .count();

        match differences.is_empty() {
            false => Err(differences),
            true => Ok(()),
        }
    }
}

/// Should a specific knowledge be filtered out
fn filter_knowledge<PT: ProtocolTypes>(
    knowledge: &Knowledge<PT>,
    whitelist: &Option<Vec<TypeId>>,
    blacklist: &Option<Vec<TypeId>>,
) -> bool {
    if whitelist.is_none() && blacklist.is_none() {
        return true;
    }

    if let Some(list) = whitelist {
        if !list.iter().any(|x| x == &knowledge.data.type_id()) {
            return false;
        }
    }

    if let Some(list) = blacklist {
        if list.iter().any(|x| x == &knowledge.data.type_id()) {
            return false;
        }
    }

    true
}

#[derive(Debug)]
pub struct Spawner<PB: ProtocolBehavior> {
    registry: PutRegistry<PB>,
    descriptors: HashMap<AgentName, PutDescriptor>,
    default: PutDescriptor,
}

impl<PB: ProtocolBehavior> Spawner<PB> {
    pub fn new(registry: impl Into<PutRegistry<PB>>) -> Self {
        let registry = registry.into();
        Self {
            default: registry.default().name().into(),
            registry,
            descriptors: Default::default(),
        }
    }

    #[must_use]
    pub fn with_mapping(mut self, descriptors: &[(AgentName, PutDescriptor)]) -> Self {
        self.descriptors.extend(descriptors.iter().cloned());
        self
    }

    pub fn with_default(mut self, put: impl Into<PutDescriptor>) -> Self {
        self.default = put.into();
        self
    }

    pub fn spawn(
        &self,
        claims: &GlobalClaimList<PB::Claim>,
        descriptor: &AgentDescriptor<<PB::ProtocolTypes as ProtocolTypes>::PUTConfig>,
    ) -> Result<Agent<PB>, Error> {
        let put_descriptor = self
            .descriptors
            .get(&descriptor.name)
            .cloned()
            .unwrap_or_else(|| self.default.clone());

        let factory = self
            .registry
            .find_by_id(&put_descriptor.factory)
            .ok_or_else(|| {
                Error::Agent(format!(
                    "unable to find PUT {} factory in binary",
                    &put_descriptor.factory
                ))
            })?;

        let put = factory.create(descriptor, claims, &put_descriptor.options)?;
        Ok(Agent::new(descriptor.clone(), put))
    }
}

impl<PB: ProtocolBehavior + PartialEq> PartialEq for Spawner<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.registry == other.registry
            && self.descriptors == other.descriptors
            && self.default == other.default
    }
}

impl<PB: ProtocolBehavior> Clone for Spawner<PB> {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            descriptors: self.descriptors.clone(),
            default: self.default.clone(),
        }
    }
}

/// The [`TraceContext`] represents the state of an execution.
///
/// The [`TraceContext`] contains a list of [`EvaluatedTerm`], which is known as the knowledge
/// of the attacker. [`EvaluatedTerm`] can contain data of various types like for example
/// client and server extensions, cipher suits or session ID It also holds the concrete
/// references to the [`Agent`]s and the underlying streams, which contain the messages
/// which have need exchanged and are not yet processed by an output step.
#[derive(Debug)]
pub struct TraceContext<PB: ProtocolBehavior> {
    /// The knowledge of the attacker
    pub knowledge_store: KnowledgeStore<PB::ProtocolTypes>,
    agents: Vec<Agent<PB>>,
    claims: GlobalClaimList<PB::Claim>,

    spawner: Spawner<PB>,

    phantom: PhantomData<PB>,
    /// The number of steps that have been successfully executed
    pub executed_until: usize,
}

impl<PB: ProtocolBehavior> fmt::Display for TraceContext<PB> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Knowledge [not displaying other fields] (size={}):",
            self.knowledge_store.raw_knowledge.len()
        )?;
        for k in &self.knowledge_store.raw_knowledge {
            write!(f, "\n   {k},          --  {k:?}")?;
        }
        Ok(())
    }
}

impl<PB: ProtocolBehavior + PartialEq> PartialEq for TraceContext<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.agents == other.agents
            && self.spawner == other.spawner
            && format!("{:?}", self.knowledge_store.raw_knowledge)
                == format!("{:?}", other.knowledge_store.raw_knowledge)
            && format!("{:?}", self.claims) == format!("{:?}", other.claims)
    }
}

impl<PB: ProtocolBehavior> TraceContext<PB> {
    #[must_use]
    pub fn new(spawner: Spawner<PB>) -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName. A rename of an Agent does not interfere with this.
        let claims = GlobalClaimList::<PB::Claim>::new();

        Self {
            knowledge_store: KnowledgeStore::new(),
            agents: vec![],
            claims,
            spawner,
            phantom: Default::default(),
            executed_until: 0,
        }
    }

    pub fn verify_security_violations(&self) -> Result<(), Error> {
        let claims = self.claims.deref_borrow();
        claims.log();
        if let Some(msg) = PB::SecurityViolationPolicy::check_violation(claims.slice()) {
            // [TODO] Lucca: versus checking at each step ? Could detect violation earlier, before a
            // blocking state is reached ? [BENCH] benchmark the efficiency loss of doing so
            // Max: We only check for Finished claims right now, so its fine to check only at the
            // end
            return Err(Error::SecurityClaim(msg));
        }
        Ok(())
    }

    /// Count the number of sub-messages of type `type_id` with the correct source
    pub fn number_matching_message_with_source(
        &self,
        source: Source,
        type_id: TypeId,
        tls_message_type: &Option<<PB::ProtocolTypes as ProtocolTypes>::Matcher>,
    ) -> usize {
        self.knowledge_store
            .number_matching_message_with_source(source, type_id, tls_message_type)
    }

    /// Count the number of sub-messages of type `type_id` in the output message.
    pub fn number_matching_message(
        &self,
        type_id: TypeId,
        tls_message_type: &Option<<PB::ProtocolTypes as ProtocolTypes>::Matcher>,
    ) -> usize {
        self.knowledge_store
            .number_matching_message(type_id, tls_message_type)
    }

    #[must_use]
    pub fn find_claim(
        &self,
        agent_name: AgentName,
        query_type_shape: TypeShape<PB::ProtocolTypes>,
    ) -> Option<Box<dyn EvaluatedTerm<PB::ProtocolTypes>>> {
        self.claims
            .deref_borrow()
            .find_last_claim(agent_name, query_type_shape)
            .map(super::claims::Claim::inner)
    }

    /// Returns the variable which matches best -> highest specificity
    /// If we want a variable with lower specificity, then we can just query less specific
    pub fn find_variable(
        &self,
        query_type_shape: TypeShape<PB::ProtocolTypes>,
        query: &Query<<PB::ProtocolTypes as ProtocolTypes>::Matcher>,
    ) -> Option<&(dyn EvaluatedTerm<PB::ProtocolTypes>)> {
        log::trace!(
            "Looking for variable in {:?} with query {:?}",
            self.knowledge_store,
            query
        );
        self.knowledge_store.find_variable(query_type_shape, query)
    }

    pub fn spawn(
        &mut self,
        descriptor: &AgentDescriptor<<PB::ProtocolTypes as ProtocolTypes>::PUTConfig>,
    ) -> Result<(), Error> {
        let agent = self.spawner.spawn(&self.claims, descriptor)?;
        self.agents.push(agent);

        Ok(())
    }

    pub fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent<PB>, Error> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.name() == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {name}. Did you forget to call spawn_agents?"
            ))
        })
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent<PB>, Error> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.name() == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {name}. Did you forget to call spawn_agents?"
            ))
        })
    }

    #[must_use]
    pub fn agents_successful(&self) -> bool {
        self.agents
            .iter()
            .all(super::agent::Agent::is_state_successful)
    }

    pub fn compare(&self, other: &Self) -> Result<(), Vec<TraceDifference>> {
        let mut res = vec![];

        // Decrypting knowledges
        let terms: Vec<Term<PB::ProtocolTypes>> =
            PB::ProtocolTypes::differential_fuzzing_terms_to_eval();

        let mut self_store = KnowledgeStore::new();
        let mut other_store = KnowledgeStore::new();

        for t in terms {
            let self_eval = t.evaluate_dy(self);
            let other_eval = t.evaluate_dy(other);
            if let Ok(decrypted) = self_eval {
                self_store.add_raw_boxed_knowledge(
                    decrypted,
                    None,
                    Source::Label(Some("Decryption".into())),
                    None,
                );
            }
            if let Ok(decrypted) = other_eval {
                other_store.add_raw_boxed_knowledge(
                    decrypted,
                    None,
                    Source::Label(Some("Decryption".into())),
                    None,
                );
            }
        }

        // Comparing the claims
        res.extend(
            self.claims
                .compare(&other.claims)
                .err()
                .map_or(vec![], |x| x),
        );

        // Comparing the knowledges
        res.extend(
            self.knowledge_store
                .compare(&other.knowledge_store)
                .err()
                .map_or(vec![], |x| x),
        );

        // Comparing the computed terms
        res.extend(self_store.compare(&other_store).err().map_or(vec![], |x| x));

        if res.is_empty() {
            Ok(())
        } else {
            Err(res)
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Trace<PT: ProtocolTypes> {
    pub descriptors: Vec<AgentDescriptor<PT::PUTConfig>>,
    pub steps: Vec<Step<PT>>,
    pub prior_traces: Vec<Trace<PT>>,
}

/// Identify a step and a (prior) trace
#[derive(Clone, Debug, Deserialize, Serialize, Hash, PartialEq, Eq, Comparable)]
pub struct StepNumber {
    /// identify the trace (allow to differentiate between prior traces)
    pub trace: usize,
    /// The step number in the trace
    pub step: usize,
}

impl StepNumber {
    pub fn new(trace: usize, step: usize) -> Self {
        Self { trace, step }
    }
}

/// Store the result of a trace execution for displaying or serializing
#[derive(Serialize)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct ExecutionResult<PT: ProtocolTypes> {
    put: String,
    error: Option<String>,
    execution: TraceExecution<PT>,
}

impl<PT: ProtocolTypes> ExecutionResult<PT> {
    pub fn from<PB>(
        put: String,
        error: Option<String>,
        trace: &Trace<PT>,
        ctx: TraceContext<PB>,
        export_terms: bool,
        export_knowledges: bool,
        export_claims: bool,
    ) -> Self
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        let mut ctx = ctx;
        Self {
            put,
            error,
            execution: TraceExecution::from(
                trace,
                &mut ctx,
                export_terms,
                export_knowledges,
                export_claims,
            ),
        }
    }
}

impl<PT: ProtocolTypes> Display for ExecutionResult<PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Trace execution")?;
        writeln!(f, "PUT: {}\n", self.put)?;

        self.execution.print(f, 0)?;

        match self.error {
            None => writeln!(f, "Success"),
            Some(_) => writeln!(f, "Error : {}", self.error.clone().unwrap_or("".into())),
        }
    }
}

/// Store the result of a trace execution to be printed in the cli or serialized
/// for automated analysis
#[derive(Serialize)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct TraceExecution<PT: ProtocolTypes> {
    prior_traces: Vec<TraceExecution<PT>>,
    agents: Vec<AgentDescriptor<PT::PUTConfig>>,
    /// Total number of step in the trace
    number_of_steps: usize,
    /// Number of steps executed before error
    executed_until: usize,
    /// Execution result of each step
    steps: Vec<StepExecution<PT>>,
}

impl<PT: ProtocolTypes> TraceExecution<PT> {
    pub fn from<PB>(
        trace: &Trace<PT>,
        ctx: &mut TraceContext<PB>,
        export_terms: bool,
        export_knowledges: bool,
        export_claims: bool,
    ) -> Self
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        let mut steps = Vec::with_capacity(trace.steps.len());

        let trace_number = Self::count_prior_traces(trace) - 1;

        for (idx, step) in trace.steps.iter().enumerate() {
            let knowledges = if export_knowledges {
                let mut step_knowledges = Vec::new();
                let mut old_knowledges = Vec::new();

                mem::swap(&mut old_knowledges, &mut ctx.knowledge_store.raw_knowledge);

                for k in old_knowledges {
                    if k.step == Some(StepNumber::new(trace_number, idx)) {
                        step_knowledges.push(k.data);
                    } else {
                        ctx.knowledge_store.raw_knowledge.push(k);
                    }
                }
                Some(step_knowledges)
            } else {
                None
            };

            let claims = if export_claims {
                let mut step_claims = Vec::new();

                for c in ctx.claims.deref_borrow().iter() {
                    if c.get_step() == Some(StepNumber::new(trace_number, idx)) {
                        step_claims.push(c.inner());
                    }
                }
                Some(step_claims)
            } else {
                None
            };

            steps.push(StepExecution {
                step_number: idx,
                action: ActionType::from(step.action.clone(), export_terms),
                agent: step.agent.into(),
                knowledges,
                claims,
            });
        }

        Self {
            agents: trace.descriptors.clone(),
            number_of_steps: trace.steps.len(),
            executed_until: ctx.executed_until,
            steps,
            // right now we exclude prior traces
            prior_traces: Vec::new(),
        }
    }

    fn count_prior_traces(trace: &Trace<PT>) -> usize {
        let prior: usize = trace
            .prior_traces
            .iter()
            .fold(0, |acc, p| acc + Self::count_prior_traces(p));
        return 1 + prior;
    }

    pub fn print(&self, f: &mut std::fmt::Formatter<'_>, depth: usize) -> std::fmt::Result {
        let tabs = "\t".repeat(depth);

        for (idx, p) in self.prior_traces.iter().enumerate() {
            writeln!(f, "{tabs}==== Executing prior trace #{} ====", idx)?;
            p.print(f, depth + 1)?;
        }

        writeln!(f, "{tabs}Agents:")?;
        for (idx, agent) in self.agents.iter().enumerate() {
            writeln!(f, "{tabs}\t {}: {:?}", idx, agent)?;
        }

        writeln!(f, "{tabs} Executed until step {}", self.executed_until)?;

        writeln!(f)?;

        for s in &self.steps {
            s.print(f, depth)?;
        }

        writeln!(f, "")
    }
}

#[derive(Serialize)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct StepExecution<PT: ProtocolTypes> {
    step_number: usize,
    action: ActionType,
    agent: AgentName,
    knowledges: Option<Vec<Box<dyn EvaluatedTerm<PT>>>>,
    claims: Option<Vec<Box<dyn EvaluatedTerm<PT>>>>,
}

#[derive(Serialize)]
enum ActionType {
    Input {
        recipe: Option<String>,
        precomputations: Option<Vec<(String, String)>>,
    },
    Output,
}

impl ActionType {
    fn from<PT: ProtocolTypes>(value: Action<PT>, export_terms: bool) -> Self {
        match value {
            Input(input_action) => ActionType::Input {
                recipe: match export_terms {
                    true => Some(input_action.recipe.to_string()),
                    false => None,
                },
                precomputations: match export_terms {
                    true => Some(
                        input_action
                            .precomputations
                            .iter()
                            .map(|p| (p.label.clone().unwrap_or("".into()), p.recipe.to_string()))
                            .collect(),
                    ),
                    false => None,
                },
            },
            Action::Output(_) => ActionType::Output,
        }
    }
}

/// Allow serializing Box<dyn EvaluatedTerm<_>>
impl<PT: ProtocolTypes> Serialize for Box<dyn EvaluatedTerm<PT>> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

impl<PT: ProtocolTypes> StepExecution<PT> {
    pub fn print(&self, f: &mut std::fmt::Formatter<'_>, depth: usize) -> std::fmt::Result {
        let tabs = "\t".repeat(depth);
        writeln!(f, "{tabs}==== Executing step #{} ====", self.step_number)?;

        match &self.action {
            ActionType::Input {
                recipe,
                precomputations,
            } => {
                println!("{tabs}Action: Input (attacker -> agent.{})", self.agent);
                if let Some(p) = precomputations {
                    for (precomputation_name, precomputation_recipe) in p {
                        println!(
                            "{tabs}Precomputation {}: {}",
                            precomputation_name, precomputation_recipe
                        );
                    }
                }
                if let Some(r) = recipe {
                    println!("{tabs}Term: {}", r);
                }
            }
            ActionType::Output => {
                println!("{tabs}Action: Output (agent.{} -> attacker)", self.agent);
            }
        }

        if let Some(knowledges) = &self.knowledges {
            for k in knowledges {
                println!("{tabs}>>> {:?}", k);
            }
        }
        if let Some(claims) = &self.claims {
            for c in claims {
                println!("{tabs}+++ {:?}", c);
            }
        }

        writeln!(f, "")
    }
}

/// A [`Trace`] consists of several [`Step`]s. Each has either a [`OutputAction`] or an
/// [`InputAction`]. Each [`Step`]s references an [`Agent`] by name. Furthermore, a trace also has a
/// list of *`AgentDescriptors`* which act like a blueprint to spawn [`Agent`]s with a corresponding
/// server or client role and a specific TLs version. Essentially they are an [`Agent`] without a
/// stream.
impl<PT: ProtocolTypes> Trace<PT> {
    pub fn spawn_agents<PB: ProtocolBehavior>(
        &self,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        for descriptor in &self.descriptors {
            if let Some(reusable) = ctx
                .agents
                .iter_mut()
                .find(|existing| existing.is_reusable_with(descriptor))
            {
                // rename if it already exists and we want to reuse
                reusable.reset(descriptor.name)?;
            } else {
                // only spawn completely new if not yet existing
                ctx.spawn(descriptor)?;
            };
        }

        Ok(())
    }

    pub fn execute_until_step_wrap<PB>(
        &self,
        ctx: &mut TraceContext<PB>,
        stop_at_step: usize,
        trace_number: &mut usize,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        for trace in &self.prior_traces {
            // Call wrap function to avoid counting these sub-executions in ALL_EXEC and
            // ALL_EXEC_SUCCESS counters
            trace
                .execute_until_step_wrap(ctx, trace.steps.len(), trace_number)
                .map_err(|e| {
                    log::warn!("[execute_until_step_wrap] fail executing prior traces {trace}");
                    e
                })?;
        }

        self.spawn_agents(ctx)?;
        let steps = &self.steps[0..stop_at_step];
        ctx.executed_until = 0;
        for (i, step) in steps.iter().enumerate() {
            log::debug!("Executing step #{}", i);
            step.execute(StepNumber::new(*trace_number, i), ctx)?;

            ctx.verify_security_violations()?;
            ctx.executed_until = i + 1;
        }

        *trace_number += 1;

        Ok(())
    }

    pub fn execute_until_step<PB>(
        &self,
        ctx: &mut TraceContext<PB>,
        stop_at_step: usize,
        trace_number: &mut usize,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        ALL_EXEC.increment();
        let res = self.execute_until_step_wrap(ctx, stop_at_step, trace_number);

        if let Err(e) = res {
            match &e {
                Error::Fn(_) => ERROR_FN.increment(),
                Error::Term(_e) => ERROR_TERM.increment(),
                Error::TermBug(_e) => ERROR_TERMBUG.increment(),
                Error::Put(_) => ERROR_PUT.increment(),
                Error::Codec(_) => ERROR_CODEC.increment(),
                Error::IO(_) => ERROR_IO.increment(),
                Error::Agent(_) => ERROR_AGENT.increment(),
                Error::Stream(_) => ERROR_STREAM.increment(),
                Error::Extraction() => ERROR_EXTRACTION.increment(),
                Error::SecurityClaim(_) => {}
                Error::Difference(_) => {}
            }
            return Err(e);
        }

        ALL_EXEC_SUCCESS.increment();
        if cfg!(feature = "introspection") {
            if ctx.agents_successful() {
                ALL_EXEC_AGENT_SUCCESS.increment();
            }
        }

        Ok(())
    }

    pub fn execute<PB>(
        &self,
        ctx: &mut TraceContext<PB>,
        trace_number: &mut usize,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        self.execute_until_step(ctx, self.steps.len(), trace_number)
    }

    pub fn serialize_postcard(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(&self)
    }

    pub fn deserialize_postcard(slice: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes::<Self>(slice)
    }

    #[must_use]
    pub fn all_payloads(&self) -> Vec<&Payloads> {
        self.steps
            .iter()
            .filter_map(|e| match &e.action {
                Input(r) => Some(&r.recipe),
                _ => None,
            })
            .flat_map(|t| t.all_payloads())
            .collect()
    }

    pub fn all_payloads_mut(&mut self) -> Vec<&mut Payloads> {
        self.steps
            .iter_mut()
            .filter_map(|e| match &mut e.action {
                Input(r) => Some(&mut r.recipe),
                _ => None,
            })
            .flat_map(|t| t.all_payloads_mut())
            .collect()
    }

    #[must_use]
    pub fn is_symbolic(&self) -> bool {
        self.steps.iter().all(|e| match &e.action {
            Input(r) => r.recipe.is_symbolic(),
            _ => true,
        })
    }

    /// Remove the steps after (excluding) `after_step`
    pub fn truncate_at_step(&mut self, after_step: usize) {
        log::error!("Truncating trace at step {after_step}");
        self.steps.truncate(after_step);
    }

    /// Size of trace (summing all input sizes, counting one for output)
    pub fn size(&self) -> usize {
        self.steps.iter().fold(0, |acc, s| match &s.action {
            Action::Input(inp) => acc + inp.recipe.size(),
            Action::Output(_) => acc + 1,
        })
    }
}

impl<PT: ProtocolTypes> fmt::Debug for Trace<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trace with {} steps", self.steps.len())
    }
}

impl<PT: ProtocolTypes> fmt::Display for Trace<PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Trace:")?;
        for step in &self.steps {
            write!(f, "\n{} -> {}", step.agent, step.action)?;
        }
        Ok(())
    }
}

impl<PT: ProtocolTypes> AsRef<Self> for Trace<PT> {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Step<PT: ProtocolTypes> {
    pub agent: AgentName,
    pub action: Action<PT>,
}

impl<PT: ProtocolTypes> Step<PT> {
    pub fn execute<PB>(
        &self,
        step_number: StepNumber,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        match &self.action {
            Action::Input(input) => input.execute(self.agent, ctx).and_then(|()| {
                // NOTE force output after each InputAction step
                (OutputAction {
                    phantom: Default::default(),
                })
                .execute(self.agent, step_number, ctx)
            }),
            Action::Output(output) => output.execute(self.agent, step_number, ctx),
        }
    }
}

/// There are two action types [`OutputAction`] and [`InputAction`].
///
/// Both actions drive the internal state machine of an [`Agent`] forward by calling `progress()`.
/// The [`OutputAction`] first forwards the state machine and then extracts knowledge from the
/// TLS messages produced by the underlying stream by calling  `take_message_from_outbound(...)`.
/// The [`InputAction`] evaluates the recipe term and injects the newly produced message
/// into the *inbound channel* of the [`Agent`] referenced through the corresponding [`Step`]s
/// by calling `add_to_inbound(...)` and then drives the state machine forward.
/// Therefore, the difference is that one step *increases* the knowledge of the attacker,
/// whereas the other action *uses* the available knowledge.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub enum Action<PT: ProtocolTypes> {
    Input(InputAction<PT>),
    Output(OutputAction<PT>),
}

impl<PT: ProtocolTypes> fmt::Display for Action<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(input) => write!(f, "{input}"),
            Self::Output(output) => write!(f, "{output}"),
        }
    }
}

/// Advance the [`Agent`]'s state and process the produced output.
///
/// The [`OutputAction`] first forwards the state machine and then extracts knowledge from the TLS
/// messages produced by the underlying stream by calling  `take_message_from_outbound(...)`. An
/// output action is automatically called after each input step.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct OutputAction<PT> {
    phantom: PhantomData<PT>,
}

impl<PT: ProtocolTypes> OutputAction<PT> {
    #[must_use]
    pub fn new_step(agent: AgentName) -> Step<PT> {
        Step {
            agent,
            action: Action::Output(Self {
                phantom: Default::default(),
            }),
        }
    }

    fn execute<PB>(
        &self,
        agent_name: AgentName,
        step: StepNumber, // the current step of the trace
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        let source = Source::Agent(agent_name);
        let agent = ctx.find_agent_mut(agent_name)?;

        agent.progress()?;

        if let Some(opaque_flight) = agent.take_message_from_outbound()? {
            ctx.knowledge_store.add_raw_knowledge(
                opaque_flight.clone(),
                Some(step.clone()),
                source.clone(),
                None,
            );

            if let Ok(flight) = TryInto::<PB::ProtocolMessageFlight>::try_into(opaque_flight) {
                ctx.knowledge_store
                    .add_raw_knowledge(flight, Some(step.clone()), source, None);
            }
        }

        // Iterate on claimlist from the end to set the step number on the last claims collected
        for claim in ctx.claims.deref_borrow_mut().iter_mut().rev() {
            if claim.get_step().is_none() {
                // if the claim doesn't have a step number, it has been created during the last step
                claim.set_step(Some(step.clone()));
            } else {
                // all prior claims should already have a number
                break;
            }
        }

        Ok(())
    }
}

impl<PT: ProtocolTypes> fmt::Display for OutputAction<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputAction")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Precomputation<PT: ProtocolTypes> {
    pub label: Option<String>,
    pub recipe: Term<PT>,
}

/// Provide inputs to the [`Agent`].
///
/// The [`InputAction`] evaluates the recipe term and injects the newly produced message
/// into the *inbound channel* of the [`Agent`] referenced through the corresponding [`Step`]s
/// by calling `add_to_inbound(...)` and then drives the state machine forward.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct InputAction<PT: ProtocolTypes> {
    pub precomputations: Vec<Precomputation<PT>>,
    pub recipe: Term<PT>,
}

/// Processes messages in the inbound channel. Uses the recipe field to evaluate to a rustls Message
/// or a `MultiMessage`.
impl<PT: ProtocolTypes> InputAction<PT> {
    pub const fn new_step(agent: AgentName, recipe: Term<PT>) -> Step<PT> {
        Step {
            agent,
            action: Action::Input(Self {
                recipe,
                precomputations: vec![],
            }),
        }
    }

    fn execute<PB>(&self, agent_name: AgentName, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        for precomputation in &self.precomputations {
            let eval = precomputation.recipe.evaluate_dy(ctx)?; // We do not accept payloads in precomputation recipes
            ctx.knowledge_store.add_raw_boxed_knowledge(
                eval,
                None,
                Source::Label(precomputation.label.clone()),
                Some(precomputation.recipe.clone()),
            );
        }

        let message = self.recipe.evaluate(ctx)?;
        let agent = ctx.find_agent_mut(agent_name)?;

        agent.add_to_inbound(&message);
        agent.progress()
    }
}

impl<PT: ProtocolTypes> fmt::Display for InputAction<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputAction:\n{}", self.recipe)
    }
}

/// This macro defines the precomputation syntax to add precomputations to an input action step
///
/// Example of precomputation with TLS
///
/// ```ignore
/// input_action! {
///     // Here we are precomputing a decryption of TLS extension and using it in the following term
///     "decrypted_extensions" = term!{fn_decrypt_handshake_flight(
///         ((server, 0)/MessageFlight),
///         (@server_hello_transcript),
///         (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
///         fn_no_psk,
///         fn_named_group_secp384r1,
///         fn_true,
///         fn_seq_0  // sequence 0
///     )}
///     =>
///     // This term will be sent to the PUT by the input action
///     term!{fn_append_transcript(
///         (@server_hello_transcript),
///         (
///             // We can query our precomputation
///             (!"decrypted_extensions", 0)[
///                 Some(TlsQueryMatcher::Handshake(Some(HandshakeType::EncryptedExtensions)))
///             ] / Message
///         )
///     )}
/// };
/// ```
///
/// The following syntaxes are accepted :
/// ```ignore
/// # use puffin::input_action;
/// # use puffin::term;
/// # use puffin::trace::Precomputation;
/// # use puffin::trace::InputAction;
///
/// input_action!{term!{fn_msg()}};
/// input_action!{term!{fn_precomputation()} => term!{fn_msg()}};
/// input_action!{"this_is_a_label" = term!{fn_precomputation()} => term!{fn_msg()}};
/// input_action!{
///     "this_is_a_label" = term!{fn_precomputation_1()} =>
///         term!{fn_precomputation_2()} =>
///             term!{fn_msg()}
/// };
/// // the latter is equivalent to
/// input_action!{
///     "this_is_a_label" = term!{fn_precomputation_1()}, term!{fn_precomputation_2()} =>
///         term!{fn_msg()}
/// };
/// ```
///
/// All the previous examples respectively produce
/// ```ignore
/// # use puffin::trace::Precomputation;
/// # use puffin::trace::InputAction;
/// # use puffin::term;
/// # use crate::algebra::test_signature::fn_msg;
///
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![],
/// };
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![Precomputation{label: "".into(), recipe: term!{fn_precomputation()}}],
/// };
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![Precomputation{label: "this_is_a_label".into(), recipe:
/// term!{fn_precomputation()}}], };
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![
///         Precomputation{label: "this_is_a_label".into(), recipe: term!{fn_precomputation_1()}},
///         Precomputation{label: "".into(), recipe: term!{fn_precomputation_2()}}
///     ],
/// };
/// ```
#[macro_export]
macro_rules! input_action {
    (@internal [$($label:expr, $precomp:expr);+] $recipe:expr) => {
        InputAction {
            recipe: $recipe,
            precomputations: vec![$(Precomputation{label: $label, recipe: $precomp}),*],
        }
    };

    (@internal [$($precomps:tt)+] $other_name:literal = $other_precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; Some($other_name.into()), $other_precomp] $($tail)+ }
    };

    (@internal [$($precomps:tt)+] $other_name:literal = $other_precomp:expr, $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; Some($other_name.into()), $other_precomp] $($tail)+ }
    };

    (@internal [$($precomps:tt)+] $other_precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; None, $other_precomp] $($tail)+ }
    };

    (@internal [$($precomps:tt)+] $other_precomp:expr, $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; None, $other_precomp] $($tail)+ }
    };

    ($precomp_name:literal = $precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [Some($precomp_name.into()), $precomp] $($tail)+ }
    };

    ($precomp_name:literal = $precomp:expr , $($tail:tt)+) => {
        input_action!{@internal [Some($precomp_name.into()), $precomp] $($tail)+ }
    };

    ($precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [None, $precomp] $($tail)+ }
    };

    ($precomp:expr, $($tail:tt)+) => {
        input_action!{@internal [None, $precomp] $($tail)+ }
    };

    ($recipe:expr) => {
        InputAction {
            recipe: $recipe,
            precomputations: vec![],
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::algebra::test_signature::{
        fn_encrypt12, fn_finished, fn_new_random, fn_seq_0, fn_seq_1,
    };
    use crate::term;
    use crate::trace::{InputAction, Precomputation};

    #[test]
    fn test_input_action_macro() {
        let action0 = input_action! {term!{fn_seq_0()}};
        assert_eq!(action0.precomputations.len(), 0);

        let action1 = input_action! {
            term!{fn_new_random()} =>
                "a" = term!{fn_new_random()} =>
                    term!{
                        fn_encrypt12(fn_finished,fn_seq_0)
                    }
        };
        assert_eq!(action1.precomputations.len(), 2);
        assert_eq!(action1.precomputations[0].label, None);
        assert_eq!(action1.precomputations[1].label, Some("a".into()));

        let action2 = input_action! {
            "a" = term!{fn_new_random()}, "b" = term!{fn_finished()} =>
                term!{
                    fn_encrypt12(fn_finished,fn_seq_0)
                }
        };
        assert_eq!(action2.precomputations.len(), 2);
        assert_eq!(action2.precomputations[0].label, Some("a".into()));
        assert_eq!(action2.precomputations[1].label, Some("b".into()));

        let action3 = input_action! {
            "a" = term!{fn_new_random()} => term!{fn_finished()} =>
                term!{
                    fn_encrypt12(fn_finished,fn_seq_0)
                }
        };
        assert_eq!(action3.precomputations.len(), 2);
        assert_eq!(action3.precomputations[0].label, Some("a".into()));
        assert_eq!(action3.precomputations[1].label, None);

        let action4 = input_action! {
            term!{fn_finished()}, "a" = term!{fn_new_random()} =>
                term!{
                    fn_encrypt12(fn_finished,fn_seq_0)
                }
        };
        assert_eq!(action4.precomputations.len(), 2);
        assert_eq!(action4.precomputations[0].label, None);
        assert_eq!(action4.precomputations[1].label, Some("a".into()));

        let action5 = input_action! {
            term!{fn_finished()}, "a" = term!{fn_new_random()} =>
                "b" = term!{fn_seq_0()} =>
                    term!{fn_seq_1()} =>
                        "c" = term!{fn_seq_0()} =>
                            term!{fn_seq_0()}, "d" = term!{fn_seq_0()}, "e" = term!{fn_seq_0()} =>
                                term!{
                                    fn_encrypt12(fn_finished,fn_seq_0)
                                }
        };
        assert_eq!(action5.precomputations.len(), 8);
        assert_eq!(action5.precomputations[0].label, None);
        assert_eq!(action5.precomputations[1].label, Some("a".into()));
        assert_eq!(action5.precomputations[2].label, Some("b".into()));
        assert_eq!(action5.precomputations[3].label, None);
        assert_eq!(action5.precomputations[4].label, Some("c".into()));
        assert_eq!(action5.precomputations[5].label, None);
        assert_eq!(action5.precomputations[6].label, Some("d".into()));
        assert_eq!(action5.precomputations[7].label, Some("e".into()));
    }
}
