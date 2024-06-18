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
    protocol::{MessageResult, OpaqueProtocolMessage, ProtocolBehavior, ProtocolMessage},
    put_registry::{PutDescriptor, PutRegistry},
    stream::Stream,
    variable_data::VariableData,
};

pub trait TraceExecutor {
    type Matcher: Matcher;

    fn execute(self, trace: &Trace<Self::Matcher>) -> Result<(), Error>;
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Query<M> {
    pub agent_name: AgentName,
    pub matcher: Option<M>,
    pub counter: u16, // in case an agent sends multiple messages of the same type
}

impl<M: Matcher> fmt::Display for Query<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({}, {})[{:?}]",
            self.agent_name, self.counter, self.matcher
        )
    }
}

impl<M: Matcher> Knowledge<M> {
    pub fn specificity(&self) -> u32 {
        self.matcher.specificity()
    }
}

/// [Knowledge] describes an atomic piece of knowledge inferred by the
/// [`crate::protocol::ProtocolMessage::extract_knowledge`] function
/// [Knowledge] is made of the data, the agent that produced the output, the TLS message type and the internal type.
#[derive(Debug)]
pub struct Knowledge<M: Matcher> {
    pub agent_name: AgentName,
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
            ctx.number_matching_message(self.agent_name, data_type_id, &self.matcher)
        );
        log::trace!("Knowledge data: {:?}", self.data);
    }
}

impl<M: Matcher> fmt::Display for Knowledge<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.agent_name, self.matcher)
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
    knowledge: Vec<Knowledge<PB::Matcher>>,
    agents: Vec<Agent<PB>>,
    claims: GlobalClaimList<<PB as ProtocolBehavior>::Claim>,

    put_registry: PutRegistry<PB>,
    default_put: PutDescriptor,
    put_descriptors: HashMap<AgentName, PutDescriptor>,

    phantom: PhantomData<PB>,
}

impl<PB: ProtocolBehavior> TraceExecutor for &mut TraceContext<PB> {
    type Matcher = PB::Matcher;

    fn execute(self, trace: &Trace<Self::Matcher>) -> Result<(), Error> {
        let mut pool: Vec<Agent<PB>> = self.get_agents();

        // We reseed all PUTs' PRNG before executing a trace!
        self.put_registry.determinism_reseed_all_factories();

        for p in &trace.prior_traces {
            self.execute(p)?;

            // release agents, keep them for reuse in the pool
            pool.extend(self.get_agents().into_iter());
        }

        self.spawn_agents(&mut pool, trace)?;
        let steps = &trace.steps;
        for (i, step) in steps.iter().enumerate() {
            log::debug!("Executing step #{}", i);

            step.execute(self)?;

            // Output after each InputAction step
            if let Action::Input(_) = step.action {
                let output_step = OutputAction::<PB::Matcher>::new_step(step.agent);

                output_step.execute(self)?;
            }

            self.claims.deref_borrow().log();

            self.verify_security_violations()?;
        }

        Ok(())
    }
}

impl<'a, PB: ProtocolBehavior> TraceExecutor for TraceContextBuilder<'a, PB> {
    type Matcher = PB::Matcher;

    fn execute(self, trace: &Trace<Self::Matcher>) -> Result<(), Error> {
        self.build().execute(trace)
    }
}

impl<PB: ProtocolBehavior> fmt::Display for TraceContext<PB> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Knowledge [not displaying other fields] (size={}):",
            self.knowledge.len()
        )?;
        for k in &self.knowledge {
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
            && format!("{:?}", self.knowledge) == format!("{:?}", other.knowledge)
            && format!("{:?}", self.claims) == format!("{:?}", other.claims)
    }
}

impl<PB: ProtocolBehavior> TraceContext<PB> {
    pub fn builder(registry: &PutRegistry<PB>) -> TraceContextBuilder<PB> {
        TraceContextBuilder::new(registry)
    }

    pub fn new(put_registry: &PutRegistry<PB>, default_put: PutDescriptor) -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName.
        let claims = GlobalClaimList::new();

        Self {
            knowledge: vec![],
            agents: vec![],
            claims,
            put_descriptors: Default::default(),
            put_registry: put_registry.clone(),
            default_put,
            phantom: Default::default(),
        }
    }

    fn spawn_agents(
        &mut self,
        pool: &mut Vec<Agent<PB>>,
        trace: &Trace<PB::Matcher>,
    ) -> Result<(), Error> {
        for descriptor in &trace.descriptors {
            // NOTE only spawn completely new Agent if cannot reuse any from the pool
            let agent = if let Some(position) = pool
                .iter_mut()
                .position(|existing| existing.is_reusable_with(descriptor))
            {
                let mut reusable = pool.swap_remove(position);
                reusable.reset(descriptor.name)?;
                reusable
            } else {
                let put_descriptor = self.put_descriptor(descriptor);

                let factory = self
                    .put_registry()
                    .find_by_id(&put_descriptor.factory)
                    .ok_or_else(|| {
                        Error::Agent(format!(
                            "unable to find PUT {} factory in binary",
                            &put_descriptor.factory
                        ))
                    })?;

                let put = factory.create(descriptor, self.claims(), &put_descriptor.options)?;

                Agent::new(descriptor, put)
            };

            self.add_agent(agent);
        }

        Ok(())
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

    pub fn add_knowledge(&mut self, knowledge: Knowledge<PB::Matcher>) {
        knowledge.debug_print(self);
        self.knowledge.push(knowledge)
    }

    /// Count the number of sub-messages of type `type_id`.
    pub fn number_matching_message(
        &self,
        agent: AgentName,
        type_id: TypeId,
        tls_message_type: &Option<PB::Matcher>,
    ) -> usize {
        self.knowledge
            .iter()
            .filter(|knowledge| {
                knowledge.agent_name == agent
                    && knowledge.matcher == *tls_message_type
                    && knowledge.data.as_ref().type_id() == type_id
            })
            .count()
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
        let query_type_id: TypeId = variable.typ.into();

        let mut possibilities: Vec<&Knowledge<PB::Matcher>> = Vec::new();

        for knowledge in &self.knowledge {
            let data: &dyn VariableData = knowledge.data.as_ref();

            if query_type_id == data.type_id()
                && variable.query.agent_name == knowledge.agent_name
                && knowledge.matcher.matches(&variable.query.matcher)
            {
                possibilities.push(knowledge);
            }
        }

        possibilities.sort_by_key(|a| a.specificity());

        possibilities
            .get(variable.query.counter as usize)
            .map(|possibility| possibility.data.as_ref().boxed_any())
            .or_else(|| self.find_claim(variable.query.agent_name, variable.typ))
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

    /// Gets the PUT descriptor which should be used for all agents
    pub fn put_descriptor(&self, agent_descriptor: &AgentDescriptor) -> PutDescriptor {
        self.put_descriptors
            .get(&agent_descriptor.name)
            .cloned()
            .unwrap_or_else(|| self.default_put.clone())
    }

    pub fn agents_successful(&self) -> bool {
        self.agents.iter().all(|agent| agent.is_state_successful())
    }
}

pub struct TraceContextBuilder<'a, PB: ProtocolBehavior> {
    knowledge: Vec<Knowledge<PB::Matcher>>,

    registry: &'a PutRegistry<PB>,
    put_descriptors: HashMap<AgentName, PutDescriptor>,
    default_put: PutDescriptor,
}

impl<'a, PB: ProtocolBehavior> TraceContextBuilder<'a, PB> {
    pub fn new(registry: &'a PutRegistry<PB>) -> Self {
        Self {
            knowledge: vec![],

            registry,
            put_descriptors: Default::default(),
            default_put: PutDescriptor {
                factory: registry.default().name(),
                options: Default::default(),
            },
        }
    }

    pub fn set_default_put(mut self, put: PutDescriptor) -> Self {
        self.default_put = put;
        self
    }

    /// Makes agents use the non-default PUT
    pub fn set_put(mut self, agent_name: AgentName, put_descriptor: PutDescriptor) -> Self {
        self.put_descriptors.insert(agent_name, put_descriptor);
        self
    }

    pub fn set_puts(mut self, descriptors: &[(AgentName, PutDescriptor)]) -> Self {
        self.put_descriptors.extend(descriptors.iter().cloned());
        self
    }

    pub fn with_knowledge(mut self, knowledge: Knowledge<PB::Matcher>) -> Self {
        self.knowledge.push(knowledge);
        self
    }

    pub fn build(mut self) -> TraceContext<PB> {
        let mut result = TraceContext::new(self.registry, self.default_put);
        result.knowledge.append(&mut self.knowledge);
        result.put_descriptors.extend(self.put_descriptors);

        result
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

impl<M: Matcher> Step<M> {
    fn execute<PB>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        match &self.action {
            Action::Input(input) => input.input(self.agent, ctx),
            Action::Output(output) => output.output(self.agent, ctx),
        }
    }
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

    fn output<PB>(&self, agent_name: AgentName, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        ctx.find_agent_mut(agent_name)?.progress()?;

        while let Some(message_result) = ctx
            .find_agent_mut(agent_name)?
            .take_message_from_outbound()?
        {
            let matcher = message_result.create_matcher::<PB>();

            let MessageResult(message, opaque_message) = message_result;

            let knowledge = message
                .and_then(|message| message.extract_knowledge().ok())
                .unwrap_or_default();
            let opaque_knowledge = opaque_message.extract_knowledge()?;

            log::debug!(
                "Knowledge increased by {:?}",
                knowledge.len() + opaque_knowledge.len()
            ); // +1 because of the OpaqueMessage below

            for variable in knowledge {
                let knowledge = Knowledge::<M> {
                    agent_name,
                    matcher: matcher.clone(),
                    data: variable,
                };

                ctx.add_knowledge(knowledge)
            }

            for variable in opaque_knowledge {
                let knowledge = Knowledge::<M> {
                    agent_name,
                    matcher: None, // none because we can not trust the decoding of tls_message_type, because the message could be encrypted like in TLS 1.2
                    data: variable,
                };

                ctx.add_knowledge(knowledge)
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
        agent_name: AgentName,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let evaluated = self.recipe.evaluate(&mut |v| ctx.find_variable(v))?;
        let agent = ctx.find_agent_mut(agent_name)?;

        if let Some(msg) = evaluated.as_ref().downcast_ref::<PB::ProtocolMessage>() {
            msg.debug("Input message");
            agent.add_to_inbound(&msg.create_opaque());
        } else if let Some(opaque_message) = evaluated
            .as_ref()
            .downcast_ref::<PB::OpaqueProtocolMessage>()
        {
            opaque_message.debug("Input opaque message");
            agent.add_to_inbound(opaque_message);
        } else {
            return Err(FnError::Unknown(String::from(
                "Recipe is not a `ProtocolMessage`, `OpaqueProtocolMessage`!",
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
