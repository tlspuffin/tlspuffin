//! This module contains [`Trace`]s consisting of several [`Step`]s, of which each has either an
//! [`OutputAction`] or [`InputAction`]. This is a declarative way of modeling communication between
//! [`Agent`]s. The [`TraceContext`] holds data, also known as [`VariableData`], which is created by
//! [`Agent`]s during the concrete execution of the Trace. It also holds the [`Agent`]s with
//! the references to concrete PUT.
//!
//! # Example
//!
//! ```rust
//! use tlspuffin::agent::{AgentName, AgentDescriptor, TLSVersion};
//! use tlspuffin::trace::{Step, TraceContext, Trace, Action, InputAction, OutputAction};
//! use tlspuffin::term::{Term, signature::Signature};
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use rustls::{ProtocolVersion, CipherSuite};
//! use rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use rustls::msgs::enums::Compression;
//!
//! let client: AgentName = AgentName::first();
//! let server: AgentName = client.next();
//!
//! let trace = Trace {
//!         prior_traces: vec![],
//!         descriptors: vec![
//!             AgentDescriptor { name: client, tls_version: TLSVersion::V1_3, server: false },
//!             AgentDescriptor { name: server, tls_version: TLSVersion::V1_3, server: true },
//!         ],
//!         steps: vec![
//!             Step { agent: client, action: Action::Output(OutputAction { id: 0 })},
//!             // Client: Hello Client -> Server
//!             Step {
//!                 agent: server,
//!                 action: Action::Input(InputAction {
//!                     recipe: Term::Application(
//!                         Signature::new_function(&fn_client_hello),
//!                         vec![
//!                             Term::Variable(Signature::new_var::<ProtocolVersion>((0, 0))),
//!                             Term::Variable(Signature::new_var::<Random>((0, 0))),
//!                             Term::Variable(Signature::new_var::<SessionID>((0, 0))),
//!                             Term::Variable(Signature::new_var::<Vec<CipherSuite>>((0, 0))),
//!                             Term::Variable(Signature::new_var::<Vec<Compression>>((0, 0))),
//!                             Term::Variable(Signature::new_var::<Vec<ClientExtension>>((0, 0))),
//!                         ],
//!                     ),
//!                 }),
//!             },
//!             // further steps here
//!         ]
//! };
//! let mut ctx = TraceContext::new();
//! trace.spawn_agents(&mut ctx).unwrap();
//! trace.execute(&mut ctx).unwrap();
//! ```
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
use std::{any::TypeId, fmt::Formatter};
use std::cell::RefCell;
use std::env::var;
use std::ops::Deref;
use std::rc::Rc;

use itertools::Itertools;
use rustls::msgs::message::Message;
use rustls::msgs::message::OpaqueMessage;
use security_claims::Claim;
use serde::{Deserialize, Serialize};

use crate::{
    agent::{Agent, AgentName},
    term::{dynamic_function::TypeShape, Term},
    variable_data::{extract_knowledge, VariableData},
};
use crate::agent::AgentDescriptor;
use crate::debug::{debug_message_with_info, debug_opaque_message_with_info};
use crate::error::Error;
use crate::io::{MessageResult, Stream};
#[allow(unused)] // used in docs
use crate::io::Channel;
use crate::tls::error::FnError;
use crate::violation::is_violation;

pub type ObservedId = (u16, u16);

struct ObservedVariable {
    observed_id: ObservedId,
    data: Box<dyn VariableData>,
}

pub struct VecClaimer {
    claims: Vec<(AgentName, Claim)>,
}

impl VecClaimer {
    pub fn new() -> Self {
        Self {
            claims: vec![]
        }
    }

    pub fn claim(&mut self, name: AgentName, claim: Claim) {
        self.claims.push((name, claim));
    }
}

/// The [`TraceContext`] contains a list of [`VariableData`], which is known as the knowledge
/// of the attacker. [`VariableData`] can contain data of various types like for example
/// client and server extensions, cipher suits or session ID It also holds the concrete
/// references to the [`Agent`]s and the underlying streams, which contain the messages
/// which have need exchanged and are not yet processed by an output step.
pub struct TraceContext {
    /// The knowledge of the attacker
    knowledge: Vec<ObservedVariable>,
    agents: Vec<Agent>,
    claimer: Rc<RefCell<VecClaimer>>,
}

impl TraceContext {
    pub fn new() -> Self {
        let claimer = Rc::new(RefCell::new(VecClaimer::new()));

        Self {
            knowledge: vec![],
            agents: vec![],
            claimer,
        }
    }

    pub fn add_knowledge(&mut self, observed_id: ObservedId, data: Box<dyn VariableData>) {
        self.knowledge.push(ObservedVariable { observed_id, data })
    }

    pub fn already_known(&self, in_step_id: u16, type_id: TypeId) -> u16 {
        let known_count = self.knowledge
            .iter()
            .filter(|knowledge| knowledge.observed_id.0 == in_step_id && knowledge.data.type_id() == type_id)
            .count();
        known_count as u16
    }

    pub fn get_variable_by_type_id(
        &self,
        type_shape: TypeShape,
        observed_id: ObservedId,
    ) -> Option<&(dyn VariableData + 'static)> {
        let type_id: TypeId = type_shape.into();

        for observed in &self.knowledge {
            let data: &dyn VariableData = observed.data.as_ref();
            if type_id == data.type_id() && observed_id == observed.observed_id {
                return Some(data);
            }
        }
        None
    }

    /// Adds data to the inbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    pub fn add_to_inbound(
        &mut self,
        agent_name: AgentName,
        message: &OpaqueMessage,
    ) -> Result<(), Error> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.add_to_inbound(message))
    }

    pub fn next_state(&mut self, agent_name: AgentName) -> Result<(), Error> {
        let agent = self.find_agent_mut(agent_name)?;
        Ok(agent.stream.next_state()?)
    }

    /// Takes data from the outbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    /// See [`MemoryStream::take_message_from_outbound`]
    pub fn take_message_from_outbound(
        &mut self,
        agent_name: AgentName,
    ) -> Result<Option<MessageResult>, Error> {
        let agent = self.find_agent_mut(agent_name)?;
        Ok(agent.stream.take_message_from_outbound()?)
    }

    fn add_agent(&mut self, agent: Agent) -> AgentName {
        let name = agent.descriptor.name;
        self.agents.push(agent);
        return name;
    }

    pub fn new_openssl_agent(&mut self, descriptor: &AgentDescriptor) -> Result<AgentName, Error> {
        let agent_name = self.add_agent(Agent::new_openssl(descriptor, self.claimer.clone())?);
        return Ok(agent_name);
    }

    fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent, Error> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.descriptor.name == name)
            .ok_or(Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            )))
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent, Error> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.descriptor.name == name)
            .ok_or(Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            )))
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Trace {
    pub descriptors: Vec<AgentDescriptor>,
    pub steps: Vec<Step>,
    pub prior_traces: Vec<Trace>
}

/// A [`Trace`] consists of several [`Step`]s. Each has either a [`OutputAction`] or an [`InputAction`].
/// Each [`Step`]s references an [`Agent`] by name. Furthermore, a trace also has a list of
/// *AgentDescritptors* which act like a blueprint to spawn [`Agent`]s with a corresponding server
/// or client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
impl Trace {
    pub fn spawn_agents(&self, ctx: &mut TraceContext) -> Result<(), Error> {
        for descriptor in &self.descriptors {
            ctx.new_openssl_agent(&descriptor)?;
        }

        Ok(())
    }

    pub fn execute(&self, ctx: &mut TraceContext) -> Result<(), Error> {
        self.execute_with_listener(ctx, |_step| {})
    }

    pub fn execute_with_listener(
        &self,
        ctx: &mut TraceContext,
        execution_listener: fn(step: &Step) -> (),
    ) -> Result<(), Error> {
        let steps = &self.steps;
        for i in 0..steps.len() {
            let step = &steps[i];
            trace!("Executing step #{}", i);
            step.action.execute(step, ctx)?;

            execution_listener(step);
        }

        let claims: &Vec<(AgentName, Claim)> = &ctx.claimer.deref().borrow().claims;

        trace!(
            "Claims:\n{}",
            &claims.iter().map(|(name, claim)| format!("{}: {}", name, claim)).join("\n")
        );

        if let Some(msg) = is_violation(claims) {
            return Err(Error::SecurityClaim(msg, claims.clone()));
        }

        Ok(())
    }
}

impl fmt::Debug for Trace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Trace with {} steps", self.steps.len())
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\n", "Trace:")?;
        for step in &self.steps {
            write!(f, "{} \t({})\n", step.agent, step.action)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Step {
    pub agent: AgentName,
    pub action: Action,
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Action {
    Input(InputAction),
    Output(OutputAction),
}

impl Action {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), Error> {
        match self {
            Action::Input(input) => input.input(step, ctx),
            Action::Output(output) => output.output(step, ctx),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Action::Input(input) => write!(f, "{}", input),
            Action::Output(output) => write!(f, "{}", output),
        }
    }
}

/// The [`OutputAction`] first forwards the state machine and then extracts knowledge from the
/// TLS messages produced by the underlying stream by calling  `take_message_from_outbound(...)`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OutputAction {
    pub id: u16,
}

impl OutputAction {
    pub fn new_step(agent: AgentName, id: u16) -> Step {
        Step {
            agent,
            action: Action::Output(OutputAction { id }),
        }
    }

    fn output(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), Error> {
        ctx.next_state(step.agent)?;


        while let Some(MessageResult(message, opaque_message)) = ctx.take_message_from_outbound(step.agent)? {
            match message {
                Some(message) => {
                    debug_message_with_info(format!("Output message").as_str(), &message);
                    let knowledge = extract_knowledge(&message)?;
                    trace!("Knowledge increased by {:?}", knowledge.len());

                    for variable in knowledge {
                        let sub_id = ctx.already_known(self.id, variable.type_id());
                        trace!("New knowledge {:?}/{}", (self.id, sub_id), variable.type_name());
                        ctx.add_knowledge((self.id, sub_id), variable)
                    }
                }
                None => {}
            }

            debug_opaque_message_with_info(format!("Output opaque message").as_str(), &opaque_message);
            let sub_id = ctx.already_known(self.id,opaque_message.type_id());
            trace!("New knowledge {:?}/{}", (self.id, sub_id), opaque_message.type_name());
            ctx.add_knowledge((self.id, sub_id), Box::new(opaque_message));
        }
        Ok(())
    }
}

impl fmt::Display for OutputAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "OutputAction")
    }
}

/// The [`InputAction`] evaluates the recipe term and injects the newly produced message
/// into the *inbound channel* of the [`Agent`] referenced through the corresponding [`Step`]s
/// by calling `add_to_inbound(...)` and then drives the state machine forward.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InputAction {
    pub recipe: Term,
}

/// Processes messages in the inbound channel. Uses the recipe field to evaluate to a rustls Message
/// or a MultiMessage.
impl InputAction {
    pub fn new_step(agent: AgentName, recipe: Term) -> Step {
        Step {
            agent,
            action: Action::Input(InputAction { recipe }),
        }
    }

    fn input(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), Error> {
        // message controlled by the attacker
        let evaluated = self.recipe.evaluate(ctx)?;

        if let Some(msg) = evaluated.as_ref().downcast_ref::<Message>() {
            ctx.add_to_inbound(step.agent, &OpaqueMessage::from(msg.clone()))?;

            debug_message_with_info(format!("Input message").as_str(), msg);
        } else if let Some(opaque_message) = evaluated.as_ref().downcast_ref::<OpaqueMessage>() {
            ctx.add_to_inbound(
                step.agent,
                &opaque_message.clone(),
            )?;

            debug_opaque_message_with_info(
                format!("Input opaque message").as_str(),
                opaque_message,
            );
        } else {
            return Err(FnError::Unknown(String::from(
                "Recipe is not a `Message`, `OpaqueMessage` or `MultiMessage`!",
            ))
                .into());
        }

        ctx.next_state(step.agent)
    }
}

impl fmt::Display for InputAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "recipe: {}", self.recipe)
    }
}
