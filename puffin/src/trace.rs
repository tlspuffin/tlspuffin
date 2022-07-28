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
    borrow::{Borrow, BorrowMut},
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    convert::TryFrom,
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    rc::Rc,
    slice::Iter,
};

use itertools::Itertools;
use log::{debug, trace};
use serde::{Deserialize, Serialize};

#[allow(unused)] // used in docs
use crate::io::Channel;
use crate::{
    agent::{Agent, AgentDescriptor, AgentName},
    algebra::{dynamic_function::TypeShape, error::FnError, remove_prefix, Matcher, Term},
    claims::{Claim, GlobalClaimList, SecurityViolationPolicy},
    error::Error,
    io::MessageResult,
    protocol::{Message, OpaqueMessage, ProtocolBehavior},
    put::PutDescriptor,
    put_registry::{Factory, PutRegistry},
    variable_data::VariableData,
};

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

/// [Knowledge] describes an atomic piece of knowledge inferred
/// by the [`crate::variable_data::extract_knowledge`] function
/// [Knowledge] is made of the data, the agent that produced the output, the TLS message type and the internal type.
pub struct Knowledge<M: Matcher> {
    pub agent_name: AgentName,
    pub matcher: Option<M>,
    pub data: Box<dyn VariableData>,
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
pub struct TraceContext<PB: ProtocolBehavior + 'static> {
    /// The knowledge of the attacker
    knowledge: Vec<Knowledge<PB::Matcher>>,
    agents: Vec<Agent<PB>>,
    claims: GlobalClaimList<PB::Claim>,
    put_descriptors: HashMap<AgentName, PutDescriptor>,
    put_registry: &'static PutRegistry<PB>,
    phantom: PhantomData<PB>,
}

impl<PB: ProtocolBehavior> TraceContext<PB> {
    pub fn new(put_registry: &'static PutRegistry<PB>) -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName. A rename of an Agent does not interfere with this.
        let claims = GlobalClaimList::new();

        Self {
            knowledge: vec![],
            agents: vec![],
            claims,
            put_descriptors: Default::default(),
            put_registry,
            phantom: Default::default(),
        }
    }

    pub fn put_registry(&self) -> &PutRegistry<PB> {
        self.put_registry
    }

    pub fn claims(&self) -> &GlobalClaimList<PB::Claim> {
        &self.claims
    }

    pub fn extract_knowledge(
        &self,
        message: &PB::Message,
    ) -> Result<Vec<Box<dyn VariableData>>, Error> {
        PB::extract_knowledge(message)
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
        self.knowledge.push(knowledge)
    }

    /// Count the number of sub-messages of type [type_id] in the output message [in_step_id].
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
    pub fn find_variable(
        &self,
        query_type_shape: TypeShape,
        query: &Query<PB::Matcher>,
    ) -> Option<&(dyn VariableData)> {
        let query_type_id: TypeId = query_type_shape.into();

        let mut possibilities: Vec<&Knowledge<PB::Matcher>> = Vec::new();

        for knowledge in &self.knowledge {
            let data: &dyn VariableData = knowledge.data.as_ref();

            if query_type_id == data.type_id()
                && query.agent_name == knowledge.agent_name
                && knowledge.matcher.matches(&query.matcher)
            {
                possibilities.push(knowledge);
            }
        }

        possibilities.sort_by_key(|a| a.specificity());

        possibilities
            .get(query.counter as usize)
            .map(|possibility| possibility.data.as_ref())
    }

    /// Adds data to the inbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    pub fn add_to_inbound(
        &mut self,
        agent_name: AgentName,
        message: &PB::OpaqueMessage,
    ) -> Result<(), Error> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.put.add_to_inbound(message))
    }

    pub fn next_state(&mut self, agent_name: AgentName) -> Result<(), Error> {
        let agent = self.find_agent_mut(agent_name)?;
        agent.put.progress(&agent_name)
    }

    /// Takes data from the outbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    /// See [`MemoryStream::take_message_from_outbound`]
    pub fn take_message_from_outbound(
        &mut self,
        agent_name: AgentName,
    ) -> Result<Option<MessageResult<PB::Message, PB::OpaqueMessage>>, Error> {
        let agent = self.find_agent_mut(agent_name)?;
        agent.put.take_message_from_outbound()
    }

    fn add_agent(&mut self, agent: Agent<PB>) -> AgentName {
        let name = agent.name;
        self.agents.push(agent);
        name
    }

    pub fn new_agent(&mut self, descriptor: &AgentDescriptor) -> Result<AgentName, Error> {
        let agent_name = self.add_agent(Agent::new(self, descriptor)?);
        Ok(agent_name)
    }

    pub fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent<PB>, Error> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.name == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            ))
        })
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent<PB>, Error> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.name == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            ))
        })
    }

    /// Gets the PUT which should be used for all agents
    pub fn put_descriptor(&self, agent_descriptor: &AgentDescriptor) -> PutDescriptor {
        self.put_descriptors
            .get(&agent_descriptor.name)
            .cloned()
            .unwrap_or_else(|| {
                let factory = (self.put_registry.default)();
                PutDescriptor {
                    name: factory.put_name(),
                    options: Default::default(),
                }
            })
    }

    /// Makes agents use the non-default PUT
    pub fn set_non_default_put(&mut self, agent_name: AgentName, put_descriptor: PutDescriptor) {
        self.put_descriptors.insert(agent_name, put_descriptor);
    }

    pub fn set_non_default_puts(&mut self, descriptors: &[(AgentName, PutDescriptor)]) {
        self.put_descriptors.extend(descriptors.iter().cloned());
    }

    pub fn reset_agents(&mut self) -> Result<(), Error> {
        for agent in &mut self.agents {
            agent.reset(agent.name)?;
        }
        Ok(())
    }

    pub fn agents_successful(&self) -> bool {
        for agent in &self.agents {
            if !agent.put.is_state_successful() {
                return false;
            }
        }

        true
    }

    pub fn default_put(&self) -> Box<dyn Factory<PB>> {
        self.put_registry.default_factory()
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
/// or client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
impl<M: Matcher> Trace<M> {
    fn spawn_agents<PB: ProtocolBehavior>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error> {
        for descriptor in &self.descriptors {
            if let Some(reusable) = ctx
                .agents
                .iter_mut()
                .find(|existing| existing.put.is_reusable_with(descriptor))
            {
                // rename if it already exists and we want to reuse
                reusable.rename(descriptor.name)?;
            } else {
                // only spawn completely new if not yet existing
                ctx.new_agent(descriptor)?;
            }
        }

        Ok(())
    }

    pub fn execute<PB>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        for trace in &self.prior_traces {
            trace.spawn_agents(ctx)?;
            trace.execute(ctx)?;
            ctx.reset_agents()?;
        }
        self.spawn_agents(ctx)?;
        let steps = &self.steps;
        for (i, step) in steps.iter().enumerate() {
            debug!("Executing step #{}", i);

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
        }

        ctx.verify_security_violations()?;

        Ok(())
    }

    pub fn execute_default<PB>(&self, put_registry: &'static PutRegistry<PB>) -> TraceContext<PB>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut ctx = TraceContext::new(put_registry);
        self.execute(&mut ctx).unwrap();
        ctx
    }

    pub fn execute_with_puts<PB>(
        &self,
        put_registry: &'static PutRegistry<PB>,
        descriptors: &[(AgentName, PutDescriptor)],
    ) -> TraceContext<PB>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut ctx = TraceContext::new(put_registry);

        ctx.set_non_default_puts(descriptors);

        self.execute(&mut ctx).unwrap();
        ctx
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
/// Both actions drive the internal state machine of an [`Agent`] forward by calling `next_state()`.
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
        ctx.next_state(step.agent)?;

        while let Some(MessageResult(message_o, opaque_message)) =
            ctx.take_message_from_outbound(step.agent)?
        {
            let message_result = MessageResult(message_o, opaque_message);
            let MessageResult(message, opaque_message) = &message_result;
            let matcher = Some(PB::extract_query_matcher(&message_result));

            match &message {
                Some(message) => {
                    let knowledge = ctx.extract_knowledge(message)?;

                    debug!("Knowledge increased by {:?}", knowledge.len() + 1); // +1 because of the OpaqueMessage below

                    for variable in knowledge {
                        let data_type_id = variable.as_ref().type_id();

                        let counter =
                            ctx.number_matching_message(step.agent, data_type_id, &matcher);
                        let knowledge = Knowledge::<M> {
                            agent_name: step.agent,
                            matcher: matcher.clone(),
                            data: variable,
                        };
                        debug!(
                            "New knowledge {}: {}  (counter: {})",
                            &knowledge,
                            remove_prefix(knowledge.data.type_name()),
                            counter
                        );
                        trace!("Knowledge data: {:?}", knowledge.data);
                        ctx.add_knowledge(knowledge)
                    }
                }
                None => {}
            }

            let type_id = std::any::Any::type_id(opaque_message);
            let knowledge = Knowledge::<M> {
                agent_name: step.agent,
                matcher: None, // none because we can not trust the decoding of tls_message_type, because the message could be encrypted like in TLS 1.2
                data: Box::new(message_result.1),
            };

            let counter = ctx.number_matching_message(step.agent, type_id, &None);
            debug!(
                "New knowledge {}: {} (counter: {})",
                &knowledge,
                remove_prefix(knowledge.data.type_name()),
                counter
            );
            ctx.add_knowledge(knowledge);
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
        // message controlled by the attacker
        let evaluated = self.recipe.evaluate(ctx)?;

        if let Some(msg) = evaluated.as_ref().downcast_ref::<PB::Message>() {
            msg.debug("Input message");

            ctx.add_to_inbound(step.agent, &msg.create_opaque())?;
        } else if let Some(opaque_message) = evaluated.as_ref().downcast_ref::<PB::OpaqueMessage>()
        {
            opaque_message.debug("Input opaque message");
            ctx.add_to_inbound(step.agent, opaque_message)?;
        } else {
            return Err(FnError::Unknown(String::from(
                "Recipe is not a `Message`, `OpaqueMessage` or `MultiMessage`!",
            ))
            .into());
        }

        ctx.next_state(step.agent)
    }
}

impl<M: Matcher> fmt::Display for InputAction<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputAction:\n{}", self.recipe)
    }
}
