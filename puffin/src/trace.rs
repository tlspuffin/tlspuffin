//! This module define the execution [`Trace`]s.
//!
//! Each [`Trace`]s consist of several [`Step`]s, of which each has either an [`OutputAction`] or
//! [`InputAction`]. This is a declarative way of modeling communication between [`Agent`]s. The
//! [`TraceContext`] holds data, also known as [`VariableData`], which is created by [`Agent`]s
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
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::vec::IntoIter;

use clap::error::Result;
use serde::{Deserialize, Serialize};

use crate::agent::{Agent, AgentDescriptor, AgentName};
use crate::algebra::bitstrings::Payloads;
use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::{remove_prefix, Matcher, Term, TermType};
use crate::claims::{Claim, GlobalClaimList, SecurityViolationPolicy};
use crate::error::Error;
use crate::protocol::{ExtractKnowledge, ProtocolBehavior};
use crate::put::{PutDescriptor, PutOptions};
use crate::put_registry::PutRegistry;
use crate::stream::Stream;
use crate::trace::Action::Input;
use crate::variable_data::VariableData;

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
    Label(String),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Agent(x) => write!(f, "agent:{}", x),
            Self::Label(x) => write!(f, "label:{}", x),
        }
    }
}

/// [Knowledge] describes an atomic piece of knowledge inferred by the
/// [`crate::protocol::ExtractKnowledge::extract_knowledge`] function
/// [Knowledge] is made of the data, the source of the output, the
/// TLS message type and the internal type.
#[derive(Debug)]
pub struct Knowledge<'a, M: Matcher> {
    pub source: &'a Source,
    pub matcher: Option<M>,
    pub data: &'a dyn VariableData,
}

/// [RawKnowledge] stores
#[derive(Debug)]
pub struct RawKnowledge<M: Matcher> {
    pub source: Source,
    pub matcher: Option<M>,
    pub data: Box<dyn ExtractKnowledge<M>>,
}

impl<M: Matcher> fmt::Display for RawKnowledge<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

impl<'a, M: Matcher> IntoIterator for &'a RawKnowledge<M> {
    type IntoIter = IntoIter<Knowledge<'a, M>>;
    type Item = Knowledge<'a, M>;

    fn into_iter(self) -> Self::IntoIter {
        let mut knowledges = vec![];
        let _ = self
            .data
            .extract_knowledge(&mut knowledges, self.matcher.clone(), &self.source);
        knowledges.into_iter()
    }
}

impl<M: Matcher> Knowledge<'_, M> {
    pub fn specificity(&self) -> u32 {
        self.matcher.specificity()
    }
}

impl<M: Matcher> Knowledge<'_, M> {
    pub fn debug_print<PB>(&self, ctx: &TraceContext<PB>, source: &Source)
    where
        PB: ProtocolBehavior<Matcher = M>,
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

impl<M: Matcher> fmt::Display for Knowledge<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

#[derive(Debug, Default)]
pub struct KnowledgeStore<PB: ProtocolBehavior> {
    raw_knowledge: Vec<RawKnowledge<PB::Matcher>>,
}

impl<PB: ProtocolBehavior> KnowledgeStore<PB> {
    pub fn new() -> Self {
        Self {
            raw_knowledge: vec![],
        }
    }

    pub fn add_raw_knowledge<T: ExtractKnowledge<PB::Matcher> + 'static>(
        &mut self,
        data: T,
        source: Source,
    ) {
        log::trace!("Adding raw knowledge for {:?}", &data);

        self.raw_knowledge.push(RawKnowledge {
            source,
            matcher: None,
            data: Box::new(data),
        });
    }

    pub fn number_matching_message_with_source(
        &self,
        source: Source,
        type_id: TypeId,
        tls_message_type: &Option<PB::Matcher>,
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
        tls_message_type: &Option<PB::Matcher>,
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
        query_type_shape: TypeShape,
        query: &Query<PB::Matcher>,
    ) -> Option<&(dyn VariableData)> {
        let query_type_id: TypeId = query_type_shape.into();

        let mut possibilities: Vec<Knowledge<PB::Matcher>> = self
            .raw_knowledge
            .iter()
            .filter(|raw| (query.source.is_none() || query.source.as_ref().unwrap() == &raw.source))
            .flatten()
            .filter(|knowledge| {
                query_type_id == knowledge.data.type_id()
                    && knowledge.matcher.matches(&query.matcher)
            })
            .collect();

        possibilities.sort_by_key(|a| a.specificity());

        possibilities
            .get(query.counter as usize)
            .map(|possibility| possibility.data)
    }
}

/// The [`TraceContext`] represents the state of an execution.
///
/// The [`TraceContext`] contains a list of [`VariableData`], which is known as the knowledge
/// of the attacker. [`VariableData`] can contain data of various types like for example
/// client and server extensions, cipher suits or session ID It also holds the concrete
/// references to the [`Agent`]s and the underlying streams, which contain the messages
/// which have need exchanged and are not yet processed by an output step.
#[derive(Debug)]
pub struct TraceContext<PB: ProtocolBehavior> {
    /// The knowledge of the attacker
    pub knowledge_store: KnowledgeStore<PB>,
    agents: Vec<Agent<PB>>,
    claims: GlobalClaimList<<PB as ProtocolBehavior>::Claim>,

    put_registry: PutRegistry<PB>,
    deterministic_put: bool,
    default_put_options: PutOptions,
    non_default_put_descriptors: HashMap<AgentName, PutDescriptor>,

    phantom: PhantomData<PB>,
}

impl<PB: ProtocolBehavior> fmt::Display for TraceContext<PB> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Knowledge [not displaying other fields] (size={}):",
            self.knowledge_store.raw_knowledge.len()
        )?;
        for k in &self.knowledge_store.raw_knowledge {
            write!(f, "\n   {},          --  {:?}", k, k)?;
        }
        Ok(())
    }
}

impl<PB: ProtocolBehavior + PartialEq> PartialEq for TraceContext<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.agents == other.agents
            && self.put_registry == other.put_registry
            && self.deterministic_put == other.deterministic_put
            && self.default_put_options == other.default_put_options
            && self.non_default_put_descriptors == other.non_default_put_descriptors
            && format!("{:?}", self.knowledge_store.raw_knowledge)
                == format!("{:?}", other.knowledge_store.raw_knowledge)
            && format!("{:?}", self.claims) == format!("{:?}", other.claims)
    }
}

impl<PB: ProtocolBehavior> TraceContext<PB> {
    pub fn new(put_registry: &PutRegistry<PB>, default_put_options: PutOptions) -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName. A rename of an Agent does not interfere with this.
        let claims = GlobalClaimList::new();

        Self {
            knowledge_store: KnowledgeStore::new(),
            agents: vec![],
            claims,
            non_default_put_descriptors: Default::default(),
            put_registry: put_registry.clone(),
            deterministic_put: false,
            phantom: Default::default(),
            default_put_options,
        }
    }

    pub fn put_registry(&self) -> &PutRegistry<PB> {
        &self.put_registry
    }

    pub fn claims(&self) -> &GlobalClaimList<PB::Claim> {
        &self.claims
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
        tls_message_type: &Option<PB::Matcher>,
    ) -> usize {
        self.knowledge_store
            .number_matching_message_with_source(source, type_id, tls_message_type)
    }

    /// Count the number of sub-messages of type `type_id` in the output message.
    pub fn number_matching_message(
        &self,
        type_id: TypeId,
        tls_message_type: &Option<PB::Matcher>,
    ) -> usize {
        self.knowledge_store
            .number_matching_message(type_id, tls_message_type)
    }

    pub fn find_claim(
        &self,
        agent_name: AgentName,
        query_type_shape: TypeShape,
    ) -> Option<Box<dyn Any>> {
        self.claims
            .deref_borrow()
            .find_last_claim(agent_name, query_type_shape)
            .map(|claim| claim.inner())
    }

    /// Returns the variable which matches best -> highest specificity
    /// If we want a variable with lower specificity, then we can just query less specific
    pub fn find_variable(
        &self,
        query_type_shape: TypeShape,
        query: &Query<PB::Matcher>,
    ) -> Option<&(dyn VariableData)> {
        self.knowledge_store.find_variable(query_type_shape, query)
    }

    fn add_agent(&mut self, agent: Agent<PB>) -> AgentName {
        let name = agent.name();
        self.agents.push(agent);
        name
    }

    pub fn new_agent(&mut self, descriptor: &AgentDescriptor) -> Result<AgentName, Error> {
        let put_descriptor = self.put_descriptor(descriptor);

        let (_, factory) = self
            .put_registry()
            .puts()
            .find(|(_, factory)| factory.name() == put_descriptor.factory)
            .ok_or_else(|| {
                Error::Agent(format!(
                    "unable to find PUT {} factory in binary",
                    &put_descriptor.factory
                ))
            })?;

        let put = factory.create(descriptor, &self.claims, &put_descriptor.options)?;
        let agent = Agent::new(descriptor, put, put_descriptor);

        self.add_agent(agent);

        Ok(descriptor.name)
    }

    pub fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent<PB>, Error> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.name() == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            ))
        })
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent<PB>, Error> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.name() == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            ))
        })
    }

    /// Gets the PUT descriptor which should be used for all agents
    pub fn put_descriptor(&self, agent_descriptor: &AgentDescriptor) -> PutDescriptor {
        self.non_default_put_descriptors
            .get(&agent_descriptor.name)
            .cloned()
            .unwrap_or_else(|| self.default_put_descriptor())
    }

    fn default_put_descriptor(&self) -> PutDescriptor {
        let factory = self.put_registry.default();
        PutDescriptor::new(factory.name(), self.default_put_options.clone())
    }

    /// Makes agents use the non-default PUT
    pub fn set_non_default_put(&mut self, agent_name: AgentName, put_descriptor: PutDescriptor) {
        self.non_default_put_descriptors
            .insert(agent_name, put_descriptor);
    }

    pub fn set_non_default_puts(&mut self, descriptors: &[(AgentName, PutDescriptor)]) {
        self.non_default_put_descriptors
            .extend(descriptors.iter().cloned());
    }

    pub fn reset_agents(&mut self) -> Result<(), Error> {
        for agent in &mut self.agents {
            agent.reset(agent.name())?;
        }
        Ok(())
    }

    pub fn agents_successful(&self) -> bool {
        self.agents
            .iter()
            .all(|agent| agent.put().is_state_successful())
    }

    pub fn set_deterministic(&mut self, deterministic: bool) {
        self.deterministic_put = deterministic;
    }
}

#[derive(Clone, Deserialize, Serialize, Hash)]
#[serde(bound = "M: Matcher")]
pub struct Trace<M: Matcher> {
    pub descriptors: Vec<AgentDescriptor>,
    pub steps: Vec<Step<M>>,
    pub prior_traces: Vec<Trace<M>>,
}

/// A [`Trace`] consists of several [`Step`]s. Each has either a [`OutputAction`] or an
/// [`InputAction`]. Each [`Step`]s references an [`Agent`] by name. Furthermore, a trace also has a
/// list of *AgentDescriptors* which act like a blueprint to spawn [`Agent`]s with a corresponding
/// server or client role and a specific TLs version. Essentially they are an [`Agent`] without a
/// stream.
impl<M: Matcher> Trace<M> {
    pub fn spawn_agents<PB: ProtocolBehavior>(
        &self,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error> {
        for descriptor in &self.descriptors {
            let name = if let Some(reusable) = ctx
                .agents
                .iter_mut()
                .find(|existing| existing.put().is_reusable_with(descriptor))
            {
                // rename if it already exists and we want to reuse
                reusable.rename(descriptor.name)?;
                descriptor.name
            } else {
                // only spawn completely new if not yet existing
                ctx.new_agent(descriptor)?
            };

            if ctx.deterministic_put {
                if let Ok(agent) = ctx.find_agent_mut(name) {
                    if let Err(err) = agent.put_mut().determinism_reseed() {
                        log::warn!("Unable to make agent {} deterministic: {}", name, err)
                    }
                }
            }
        }

        Ok(())
    }

    pub fn execute_until_step<PB>(
        &self,
        ctx: &mut TraceContext<PB>,
        nb_steps: usize,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        // We reseed all PUTs before executing a trace!
        ctx.put_registry.determinism_reseed_all_factories();

        for trace in &self.prior_traces {
            trace.execute(ctx)?;
            ctx.reset_agents()?;
        }
        self.spawn_agents(ctx)?;
        let steps = &self.steps[0..nb_steps];
        for (i, step) in steps.iter().enumerate() {
            log::debug!("Executing step #{}", i);
            step.execute(ctx)?;

            ctx.verify_security_violations()?;
        }

        Ok(())
    }

    pub fn execute<PB>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        self.execute_until_step(ctx, self.steps.len())
    }

    pub fn execute_deterministic<PB>(
        &self,
        put_registry: &PutRegistry<PB>,
        default_put_options: PutOptions,
    ) -> Result<TraceContext<PB>, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut ctx = TraceContext::new(put_registry, default_put_options);
        ctx.set_deterministic(true);
        self.execute(&mut ctx)?;
        Ok(ctx)
    }

    pub fn execute_with_non_default_puts<PB>(
        &self,
        put_registry: &PutRegistry<PB>,
        descriptors: &[(AgentName, PutDescriptor)],
    ) -> Result<TraceContext<PB>, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut ctx = TraceContext::new(put_registry, Default::default());

        ctx.set_non_default_puts(descriptors);

        self.execute(&mut ctx)?;
        Ok(ctx)
    }

    pub fn serialize_postcard(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(&self)
    }

    pub fn deserialize_postcard(slice: &[u8]) -> Result<Trace<M>, postcard::Error> {
        postcard::from_bytes::<Trace<M>>(slice)
    }

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

    pub fn is_symbolic(&self) -> bool {
        self.steps.iter().all(|e| match &e.action {
            Input(r) => r.recipe.is_symbolic(),
            _ => true,
        })
    }
}

impl<M: Matcher> fmt::Debug for Trace<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trace with {} steps", self.steps.len())
    }
}

impl<M: Matcher> fmt::Display for Trace<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Trace:")?;
        for step in &self.steps {
            write!(f, "\n{} -> {}", step.agent, step.action)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "M: Matcher")]
pub struct Step<M: Matcher> {
    pub agent: AgentName,
    pub action: Action<M>,
}

impl<M: Matcher> Step<M> {
    pub fn execute<PB>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        match &self.action {
            Action::Input(input) => input.execute(self.agent, ctx).and_then(|_| {
                // NOTE force output after each InputAction step
                (OutputAction {
                    phantom: Default::default(),
                })
                .execute(self.agent, ctx)
            }),
            Action::Output(output) => output.execute(self.agent, ctx),
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
#[serde(bound = "M: Matcher")]
pub enum Action<M: Matcher> {
    Input(InputAction<M>),
    Output(OutputAction<M>),
}

impl<M: Matcher> fmt::Display for Action<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Input(input) => write!(f, "{}", input),
            Action::Output(output) => write!(f, "{}", output),
        }
    }
}

/// Advance the [`Agent`]'s state and process the produced output.
///
/// The [`OutputAction`] first forwards the state machine and then extracts knowledge from the TLS
/// messages produced by the underlying stream by calling  `take_message_from_outbound(...)`. An
/// output action is automatically called after each input step.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct OutputAction<M> {
    phantom: PhantomData<M>,
}

impl<M: Matcher> OutputAction<M> {
    pub fn new_step(agent: AgentName) -> Step<M> {
        Step {
            agent,
            action: Action::Output(OutputAction {
                phantom: Default::default(),
            }),
        }
    }

    fn execute<PB>(&self, agent_name: AgentName, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let source = Source::Agent(agent_name);
        let agent = ctx.find_agent_mut(agent_name)?;

        agent.progress()?;

        if let Some(opaque_flight) = agent.take_message_from_outbound()? {
            ctx.knowledge_store
                .add_raw_knowledge(opaque_flight.clone(), source.clone());

            if let Ok(flight) = TryInto::<PB::ProtocolMessageFlight>::try_into(opaque_flight) {
                ctx.knowledge_store.add_raw_knowledge(flight, source);
            }
        }

        Ok(())
    }
}

impl<M: Matcher> fmt::Display for OutputAction<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputAction")
    }
}

/// Provide inputs to the [`Agent`].
///
/// The [`InputAction`] evaluates the recipe term and injects the newly produced message
/// into the *inbound channel* of the [`Agent`] referenced through the corresponding [`Step`]s
/// by calling `add_to_inbound(...)` and then drives the state machine forward.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "M: Matcher")]
pub struct InputAction<M: Matcher> {
    pub recipe: Term<M>,
}

/// Processes messages in the inbound channel. Uses the recipe field to evaluate to a rustls Message
/// or a MultiMessage.
impl<M: Matcher> InputAction<M> {
    pub fn new_step(agent: AgentName, recipe: Term<M>) -> Step<M> {
        Step {
            agent,
            action: Action::Input(InputAction { recipe }),
        }
    }

    fn execute<PB: ProtocolBehavior>(
        &self,
        agent_name: AgentName,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let message = self.recipe.evaluate(ctx)?;
        let agent = ctx.find_agent_mut(agent_name)?;

        agent.add_to_inbound(&message);
        agent.progress()
    }
}

impl<M: Matcher> fmt::Display for InputAction<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputAction:\n{}", self.recipe)
    }
}
