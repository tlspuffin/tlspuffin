//! This module contains [`Trace`]s consisting of several [`Step`]s, of which each has either an
//! [`OutputAction`] or [`InputAction`]. This is a declarative way of modeling communication between
//! [`Agent`]s. The [`TraceContext`] holds data, also known as [`VariableData`], which is created by
//! [`Agent`]s during the concrete execution of the Trace. It also holds the [`Agent`]s with
//! the references to concrete PUT.
//!
//! ### Serializability of Traces
//!
//! Each trace is serializable to JSON or even binary data. This helps at reproducing discovered
//! security vulnerabilities during fuzzing. If a trace triggers a security vulnerability we can
//! store it on disk and replay it when investigating the case.
//! As traces depend on concrete implementations as discussed in the next section we need to link
//! serialized data like strings or numerical IDs to functions implemented in Rust.
//!

use core::fmt;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
};

use clap::error::Result;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

#[allow(unused)] // used in docs
use crate::stream::Channel;
use crate::{
    agent::{Agent, AgentDescriptor, AgentName},
    algebra::{
        atoms::Variable, dynamic_function::TypeShape, error::FnError, remove_prefix, Matcher, Term,
    },
    claims::{Claim, GlobalClaimList, SecurityViolationPolicy},
    error::Error,
    protocol::{
        ExtractKnowledge, OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolBehavior,
        ProtocolMessage, ProtocolMessageFlight,
    },
    put_registry::{PutDescriptor, PutRegistry},
    stream::Stream,
    variable_data::VariableData,
};

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

impl<M: Matcher> Knowledge<M> {
    pub fn specificity(&self) -> u32 {
        self.matcher.specificity()
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
pub struct Knowledge<M: Matcher> {
    pub source: Source,
    pub matcher: Option<M>,
    pub data: Box<dyn VariableData>,
}

impl<M: Matcher> Knowledge<M> {
    pub fn debug_print<PB>(&self, ctx: &TraceContext<PB>)
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let data_type_id = self.data.as_ref().type_id();
        log::debug!(
            "New knowledge {}: {}  (counter: {})",
            &self,
            remove_prefix(self.data.type_name()),
            ctx.number_matching_message_with_source(
                self.source.clone(),
                data_type_id,
                &self.matcher
            )
        );
        log::trace!("Knowledge data: {:?}", self.data);
    }
}

impl<M: Matcher> fmt::Display for Knowledge<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

#[derive(Debug, Default)]
pub struct KnowledgeStore<PB: ProtocolBehavior> {
    knowledge: Vec<Knowledge<PB::Matcher>>,
}

impl<PB: ProtocolBehavior> KnowledgeStore<PB> {
    pub fn new() -> Self {
        Self { knowledge: vec![] }
    }

    pub fn add_knowledge(&mut self, knowledge: Knowledge<PB::Matcher>) {
        self.knowledge.push(knowledge);
    }

    pub fn do_extract_knowledge<T: ExtractKnowledge<PB::Matcher> + 'static>(
        &mut self,
        data: T,
        source: Source,
    ) -> Result<usize, Error> {
        let count_before = self.knowledge.len();
        log::trace!("Extracting knowledge on : {:?}", data);
        data.extract_knowledge(&mut self.knowledge, None, &source)?;

        Ok(self.knowledge.len() - count_before)
    }

    pub fn number_matching_message_with_source(
        &self,
        source: Source,
        type_id: TypeId,
        tls_message_type: &Option<PB::Matcher>,
    ) -> usize {
        self.knowledge
            .iter()
            .filter(|knowledge| {
                knowledge.source == source
                    && knowledge.matcher == *tls_message_type
                    && knowledge.data.type_id() == type_id
            })
            .count()
    }

    /// Count the number of sub-messages of type `type_id` in the output message.
    pub fn number_matching_message(
        &self,
        type_id: TypeId,
        tls_message_type: &Option<PB::Matcher>,
    ) -> usize {
        self.knowledge
            .iter()
            .filter(|knowledge| {
                knowledge.matcher == *tls_message_type && knowledge.data.type_id() == type_id
            })
            .count()
    }

    /// Returns the variable which matches best -> highest specificity
    /// If we want a variable with lower specificity, then we can just query less specific
    pub fn find_variable(&self, variable: &Variable<PB::Matcher>) -> Option<Box<dyn Any>> {
        let query_type_id: TypeId = variable.typ.into();

        let mut possibilities: Vec<&Knowledge<PB::Matcher>> = Vec::new();

        for knowledge in &self.knowledge {
            let data: &dyn VariableData = knowledge.data.as_ref();

            if query_type_id == data.type_id()
                && (variable.query.source.is_none()
                    || variable.query.source == Some(knowledge.source.clone()))
                && knowledge.matcher.matches(&variable.query.matcher)
            {
                possibilities.push(knowledge);
            }
        }

        possibilities.sort_by_key(|a| a.specificity());

        possibilities
            .get(variable.query.counter as usize)
            .map(|possibility| possibility.data.as_ref().boxed_any())
    }
}

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
    default_put: PutDescriptor,
    put_descriptors: HashMap<AgentName, PutDescriptor>,

    phantom: PhantomData<PB>,
}

impl<PB: ProtocolBehavior> fmt::Display for TraceContext<PB> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Knowledge [not displaying other fields] (size={}):",
            self.knowledge_store.knowledge.len()
        )?;
        for k in &self.knowledge_store.knowledge {
            write!(f, "\n   {},          --  {:?}", k, k)?;
        }
        Ok(())
    }
}

impl<PB: ProtocolBehavior + PartialEq> PartialEq for TraceContext<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.agents == other.agents
            && self.put_registry == other.put_registry
            && self.default_put == other.default_put
            && self.put_descriptors == other.put_descriptors
            && format!("{:?}", self.knowledge_store.knowledge)
                == format!("{:?}", other.knowledge_store.knowledge)
            && format!("{:?}", self.claims) == format!("{:?}", other.claims)
    }
}

impl<PB: ProtocolBehavior> TraceContext<PB> {
    pub fn new(put_registry: &PutRegistry<PB>, default_put: PutDescriptor) -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName.
        let claims = GlobalClaimList::new();

        Self {
            knowledge_store: KnowledgeStore::new(),
            agents: vec![],
            claims,
            put_registry: put_registry.clone(),
            default_put,
            put_descriptors: Default::default(),
            phantom: Default::default(),
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
        if let Some(msg) = PB::SecurityViolationPolicy::check_violation(claims.slice()) {
            // [TODO] Lucca: versus checking at each step ? Could detect violation earlier, before a blocking state is reached ? [BENCH] benchmark the efficiency loss of doing so
            // Max: We only check for Finished claims right now, so its fine to check only at the end
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
    pub fn find_variable(&self, variable: &Variable<PB::Matcher>) -> Option<Box<dyn Any>> {
        self.knowledge_store.find_variable(variable).or_else(|| {
            if let Some(Source::Agent(agent_name)) = variable.query.source {
                self.find_claim(agent_name, variable.typ)
            } else {
                todo!("Implement querying by label");
            }
        })
    }

    /// Add an `agent` to the execution context
    pub fn add_agent(&mut self, agent: Agent<PB>) {
        self.agents.push(agent);
    }

    /// Release all the agents from the execution context.
    ///
    /// Note that the retrieved agents are no longer available in the current execution context,
    /// making them unavailable for further interaction (e.g. when applying a [`Step`]). This is
    /// therefore mostly used at the end of an execution, when one wants to reuse the agents in
    /// future executions.
    pub fn get_agents(&mut self) -> Vec<Agent<PB>> {
        self.agents.drain(..).collect_vec()
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

    pub fn put_descriptor(&self, agent_descriptor: &AgentDescriptor) -> PutDescriptor {
        self.put_descriptors
            .get(&agent_descriptor.name)
            .cloned()
            .unwrap_or_else(|| self.default_put.clone())
    }

    /// Makes agents use the non-default PUT
    pub fn set_non_default_put(&mut self, agent_name: AgentName, put_descriptor: PutDescriptor) {
        self.put_descriptors.insert(agent_name, put_descriptor);
    }

    pub fn set_non_default_puts(&mut self, descriptors: &[(AgentName, PutDescriptor)]) {
        self.put_descriptors.extend(descriptors.iter().cloned());
    }

    pub fn agents_successful(&self) -> bool {
        self.agents.iter().all(|agent| agent.is_state_successful())
    }
}

#[derive(Clone, Deserialize, Serialize, Hash)]
#[serde(bound = "M: Matcher")]
pub struct Trace<M: Matcher> {
    pub descriptors: Vec<AgentDescriptor>,
    pub steps: Vec<Step<M>>,
    pub prior_traces: Vec<Trace<M>>,
}

/// A [`Trace`] consists of several [`Step`]s. Each has either a [`OutputAction`] or an [`InputAction`].
/// Each [`Step`]s references an [`Agent`] by name. Furthermore, a trace also has a list of
/// *AgentDescriptors* which act like a blueprint to spawn [`Agent`]s with a corresponding server
/// or client role and a specific TLS version. Essentially they are an [`Agent`] without a stream.
impl<M: Matcher> Trace<M> {
    fn spawn_agents<PB: ProtocolBehavior>(
        &self,
        pool: &mut Vec<Agent<PB>>,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error> {
        for descriptor in &self.descriptors {
            // NOTE only spawn completely new Agent if cannot reuse any from the pool
            let agent = if let Some(position) = pool
                .iter_mut()
                .position(|existing| existing.is_reusable_with(descriptor))
            {
                let mut reusable = pool.swap_remove(position);
                reusable.reset(descriptor.name)?;
                reusable
            } else {
                let put_descriptor = ctx.put_descriptor(descriptor);

                let factory = ctx
                    .put_registry()
                    .find_by_id(&put_descriptor.factory)
                    .ok_or_else(|| {
                        Error::Agent(format!(
                            "unable to find PUT {} factory in binary",
                            &put_descriptor.factory
                        ))
                    })?;

                let put = factory.create(ctx, descriptor)?;
                Agent::new(descriptor, put)
            };

            ctx.add_agent(agent);
        }

        Ok(())
    }

    pub fn execute<PB>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut pool: Vec<Agent<PB>> = ctx.get_agents();

        // We reseed all PUTs' PRNG before executing a trace!
        ctx.put_registry.determinism_reseed_all_factories();

        for trace in &self.prior_traces {
            trace.spawn_agents(&mut pool, ctx)?;
            trace.execute(ctx)?;

            // release agents, keep them for reuse in the pool
            pool.extend(ctx.get_agents().into_iter());
        }

        self.spawn_agents(&mut pool, ctx)?;
        let steps = &self.steps;
        for (i, step) in steps.iter().enumerate() {
            log::debug!("Executing step #{}", i);

            step.action.execute(step, ctx)?;

            // Output after each InputAction step
            match step.action {
                Action::Input(_) => {
                    let output_step = &OutputAction::<M>::new_step(step.agent);

                    output_step.action.execute(output_step, ctx)?;
                }
                Action::Output(_) => {}
            }

            ctx.claims.deref_borrow().log();

            ctx.verify_security_violations()?;
        }

        Ok(())
    }

    pub fn execute_deterministic<PB>(
        &self,
        put_registry: &PutRegistry<PB>,
        default_put: PutDescriptor,
    ) -> Result<TraceContext<PB>, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut ctx = TraceContext::new(put_registry, default_put);
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
        let default_put = PutDescriptor {
            factory: put_registry.default().name(),
            options: Default::default(),
        };
        let mut ctx = TraceContext::new(put_registry, default_put);

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

/// There are two action types [`OutputAction`] and [`InputAction`] differ.
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

impl<M: Matcher> Action<M> {
    fn execute<PB>(&self, step: &Step<M>, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        match self {
            Action::Input(input) => input.input(step, ctx),
            Action::Output(output) => output.output(step, ctx),
        }
    }
}

impl<M: Matcher> fmt::Display for Action<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Input(input) => write!(f, "{}", input),
            Action::Output(output) => write!(f, "{}", output),
        }
    }
}

/// The [`OutputAction`] first forwards the state machine and then extracts knowledge from the
/// TLS messages produced by the underlying stream by calling  `take_message_from_outbound(...)`.
/// An output action is automatically called after each input step.
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

    fn output<PB>(&self, step: &Step<M>, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let agent_name = step.agent;
        let source = Source::Agent(agent_name);
        let agent = ctx.find_agent_mut(agent_name)?;

        agent.progress()?;

        let opaque_flight_result = agent.take_message_from_outbound()?;

        if let Some(opaque_flight) = opaque_flight_result {
            let flight = TryInto::<PB::ProtocolMessageFlight>::try_into(opaque_flight.clone());

            if let Ok(num) = ctx
                .knowledge_store
                .do_extract_knowledge(opaque_flight, source.clone())
            {
                log::debug!("Knowledge increased by {}", num);
            }

            if let Ok(f) = flight {
                if let Ok(num) = ctx.knowledge_store.do_extract_knowledge(f, source) {
                    log::debug!("Knowledge increased by {}", num);
                }
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

    fn input<PB: ProtocolBehavior>(
        &self,
        step: &Step<M>,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let agent_name = step.agent;
        let evaluated = self.recipe.evaluate(&mut |v| ctx.find_variable(v))?;
        let agent = ctx.find_agent_mut(agent_name)?;

        if let Some(flight) = evaluated
            .as_ref()
            .downcast_ref::<PB::ProtocolMessageFlight>()
        {
            flight.debug("Input message flight");

            agent.add_to_inbound(&flight.clone().into());
        } else if let Some(flight) = evaluated
            .as_ref()
            .downcast_ref::<PB::OpaqueProtocolMessageFlight>()
        {
            flight.debug("Input opaque message flight");

            agent.add_to_inbound(flight);
        } else if let Some(msg) = evaluated.as_ref().downcast_ref::<PB::ProtocolMessage>() {
            msg.debug("Input message");

            let message_flight: PB::ProtocolMessageFlight = msg.clone().into();
            agent.add_to_inbound(&message_flight.into());
        } else if let Some(opaque_message) = evaluated
            .as_ref()
            .downcast_ref::<PB::OpaqueProtocolMessage>()
        {
            opaque_message.debug("Input opaque message");
            agent.add_to_inbound(&opaque_message.clone().into());
        } else {
            return Err(FnError::Unknown(String::from(
                "Recipe is not a `ProtocolMessage`, `OpaqueProtocolMessage`, `MessageFlight`, `OpaqueMessageFlight` !",
            ))
            .into());
        }

        agent.progress()
    }
}

impl<M: Matcher> fmt::Display for InputAction<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputAction:\n{}", self.recipe)
    }
}
