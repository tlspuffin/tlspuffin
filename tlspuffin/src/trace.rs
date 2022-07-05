//! This module contains [`Trace`]s consisting of several [`Step`]s, of which each has either an
//! [`OutputAction`] or [`InputAction`]. This is a declarative way of modeling communication between
//! [`Agent`]s. The [`TraceContext`] holds data, also known as [`VariableData`], which is created by
//! [`Agent`]s during the concrete execution of the Trace. It also holds the [`Agent`]s with
//! the references to concrete PUT.
//!
//! # Example
//!
//! ```rust
//! use tlspuffin::agent::{AgentName, AgentDescriptor, TLSVersion::*};
//! use tlspuffin::trace::{Step, TraceContext, Trace, Action, InputAction, OutputAction, Query, TlsMessageType};
//! use tlspuffin::algebra::{Term, signature::Signature};
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use rustls::{ProtocolVersion, CipherSuite};
//! use rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use rustls::msgs::enums::{Compression, HandshakeType};
//!
//! # let client_put = tlspuffin::put_registry::current_put();
//! # let server_put = tlspuffin::put_registry::current_put();
//!
//! let client: AgentName = AgentName::first();
//! let server: AgentName = client.next();
//!
//! let query = Query {
//!     agent_name: client,
//!     tls_message_type: Some(TlsMessageType::Handshake(Some(HandshakeType::ClientHello))),
//!     counter: 0
//! };
//! let trace = Trace {
//!     prior_traces: vec![],
//!     descriptors: vec![
//!         AgentDescriptor::new_client(client, V1_3, client_put),
//!         AgentDescriptor::new_server(server, V1_3, server_put),
//!     ],
//!     steps: vec![
//!             Step { agent: client, action: Action::Output(OutputAction { }) },
//!             // Client: Hello Client -> Server
//!             Step {
//!                 agent: server,
//!                 action: Action::Input(InputAction {
//!                     recipe: Term::Application(
//!                         Signature::new_function(&fn_client_hello),
//!                         vec![
//!                             Term::Variable(Signature::new_var::<ProtocolVersion>(query)),
//!                             Term::Variable(Signature::new_var::<Random>(query)),
//!                             Term::Variable(Signature::new_var::<SessionID>(query)),
//!                             Term::Variable(Signature::new_var::<Vec<CipherSuite>>(query)),
//!                             Term::Variable(Signature::new_var::<Vec<Compression>>(query)),
//!                             Term::Variable(Signature::new_var::<Vec<ClientExtension>>(query)),
//!                         ],
//!                     ),
//!                 }),
//!             },
//!     // further steps here
//!     ]
//! };
//! let mut ctx = TraceContext::new();
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
use std::{
    any::{Any, TypeId},
    borrow::{Borrow, BorrowMut},
    cell::{Ref, RefCell, RefMut},
    convert::TryFrom,
    ops::{Deref, DerefMut},
    rc::Rc,
    slice::Iter,
};

use itertools::Itertools;
use log::{debug, trace};
use rustls::msgs::{
    enums::{ContentType, HandshakeType},
    message::{Message, MessagePayload, OpaqueMessage, PlainMessage},
};
use serde::{Deserialize, Serialize, __private::de::Borrowed};

#[allow(unused)] // used in docs
use crate::io::Channel;
use crate::{
    agent::{Agent, AgentDescriptor, AgentName},
    algebra::{dynamic_function::TypeShape, remove_prefix, Term},
    claims::{AsAny, CheckViolation, Claim, GlobalClaimList, Policy},
    debug::{debug_message_with_info, debug_opaque_message_with_info},
    error::Error,
    extraction::extract_knowledge,
    io::MessageResult,
    tls::{error::FnError, violation::is_violation},
    variable_data::VariableData,
};

/// [MessageType] contains TLS-related typing information, this is to be distinguished from the *.typ fields
/// It uses [rustls::msgs::enums::{ContentType,HandshakeType}].
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TlsMessageType {
    ChangeCipherSpec,
    Alert,
    Handshake(Option<HandshakeType>),
    ApplicationData,
    Heartbeat,
}

impl QueryMatcher for HandshakeType {
    fn matches(&self, query: &Self) -> bool {
        query == self
    }
}

impl QueryMatcher for TlsMessageType {
    fn matches(&self, query: &TlsMessageType) -> bool {
        match query {
            TlsMessageType::Handshake(query_handshake_type) => match self {
                TlsMessageType::Handshake(handshake_type) => {
                    handshake_type.matches(query_handshake_type)
                }
                _ => false,
            },
            TlsMessageType::ChangeCipherSpec => matches!(self, TlsMessageType::ChangeCipherSpec),
            TlsMessageType::Alert => matches!(self, TlsMessageType::Alert),
            TlsMessageType::Heartbeat => matches!(self, TlsMessageType::Heartbeat),
            TlsMessageType::ApplicationData => matches!(self, TlsMessageType::ApplicationData),
        }
    }
}

impl TryFrom<&MessageResult> for TlsMessageType {
    type Error = Error;

    fn try_from(message_result: &MessageResult) -> Result<Self, Self::Error> {
        let tls_opaque_type = message_result.1.typ;
        match (tls_opaque_type, message_result) {
            (ContentType::Handshake, MessageResult(Some(message), _)) => match &message.payload {
                MessagePayload::Handshake(handshake_payload) => {
                    Ok(TlsMessageType::Handshake(Some(handshake_payload.typ)))
                }
                MessagePayload::TLS12EncryptedHandshake(_) => Ok(TlsMessageType::Handshake(None)),
                _ => Err(Error::Extraction(tls_opaque_type)),
            },
            (ContentType::Handshake, _) => Ok(TlsMessageType::Handshake(None)),
            (ContentType::ApplicationData, _) => Ok(TlsMessageType::ApplicationData),
            (ContentType::Heartbeat, _) => Ok(TlsMessageType::Heartbeat),
            (ContentType::Alert, _) => Ok(TlsMessageType::Alert),
            (ContentType::ChangeCipherSpec, _) => Ok(TlsMessageType::ChangeCipherSpec),
            (ContentType::Unknown(_), _) => Err(Error::Extraction(tls_opaque_type)),
        }
    }
}

impl TlsMessageType {
    pub fn specificity(&self) -> u32 {
        match self {
            TlsMessageType::Handshake(handshake_type) => {
                1 + match handshake_type {
                    None => 0,
                    Some(_) => 1,
                }
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Query {
    pub agent_name: AgentName,
    pub tls_message_type: Option<TlsMessageType>,
    pub counter: u16, // in case an agent sends multiple messages of the same type
}

impl Knowledge {
    pub fn specificity(&self) -> u32 {
        if let Some(tls_message_type) = self.tls_message_type {
            1 + tls_message_type.specificity()
        } else {
            0
        }
    }
}

impl<T> QueryMatcher for Option<T>
where
    T: QueryMatcher,
{
    fn matches(&self, query: &Self) -> bool {
        match (self, query) {
            (Some(inner), Some(inner_query)) => inner.matches(inner_query),
            (Some(_), None) => true, // None matches everything as query -> True
            (None, None) => true,    // None == None => True
            (None, Some(_)) => false, // None != Some => False
        }
    }
}

impl fmt::Display for Knowledge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.agent_name, self.tls_message_type)
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({}, {})[{:?}]",
            self.agent_name, self.counter, self.tls_message_type
        )
    }
}

/// [Knowledge] describes an atomic piece of knowledge inferred
/// by the [`crate::variable_data::extract_knowledge`] function
/// [Knowledge] is made of the data, the agent that produced the output, the TLS message type and the internal type.
pub struct Knowledge {
    pub agent_name: AgentName,
    pub tls_message_type: Option<TlsMessageType>,
    pub data: Box<dyn VariableData>,
}

/// The [`TraceContext`] contains a list of [`VariableData`], which is known as the knowledge
/// of the attacker. [`VariableData`] can contain data of various types like for example
/// client and server extensions, cipher suits or session ID It also holds the concrete
/// references to the [`Agent`]s and the underlying streams, which contain the messages
/// which have need exchanged and are not yet processed by an output step.
pub struct TraceContext {
    /// The knowledge of the attacker
    knowledge: Vec<Knowledge>,
    agents: Vec<Agent>,
    claims: GlobalClaimList,
}

pub trait QueryMatcher {
    fn matches(&self, query: &Self) -> bool;
}

impl TraceContext {
    pub fn new() -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName. A rename of an Agent does not interfere with this.
        let claims = GlobalClaimList::new();

        Self {
            knowledge: vec![],
            agents: vec![],
            claims,
        }
    }

    pub fn claims(&self) -> &GlobalClaimList {
        &self.claims
    }

    pub fn add_knowledge(&mut self, knowledge: Knowledge) {
        self.knowledge.push(knowledge)
    }

    /// Count the number of sub-messages of type [type_id] in the output message [in_step_id].
    pub fn number_matching_message(
        &self,
        agent: AgentName,
        type_id: TypeId,
        tls_message_type: Option<TlsMessageType>,
    ) -> u16 {
        let known_count = self
            .knowledge
            .iter()
            .filter(|knowledge| {
                knowledge.agent_name == agent
                    && knowledge.tls_message_type == tls_message_type
                    && knowledge.data.as_ref().type_id() == type_id
            })
            .count();
        known_count as u16
    }

    pub fn find_claim(
        &self,
        agent_name: AgentName,
        query_type_shape: TypeShape,
    ) -> Option<Box<dyn Any>> {
        self.claims
            .deref_borrow()
            .find_last_claim(agent_name, query_type_shape)
            .map(|claim| claim.clone_boxed_any())
    }

    /// Returns the variable which matches best -> highest specificity
    /// If we want a variable with lower specificity, then we can just query less specific
    pub fn find_variable(
        &self,
        query_type_shape: TypeShape,
        query: Query,
    ) -> Option<&(dyn VariableData)> {
        let query_type_id: TypeId = query_type_shape.into();

        let mut possibilities: Vec<&Knowledge> = Vec::new();

        for knowledge in &self.knowledge {
            let data: &dyn VariableData = knowledge.data.as_ref();

            if query_type_id == data.type_id()
                && query.agent_name == knowledge.agent_name
                && knowledge.tls_message_type.matches(&query.tls_message_type)
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
        message: &OpaqueMessage,
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
    ) -> Result<Option<MessageResult>, Error> {
        let agent = self.find_agent_mut(agent_name)?;
        agent.put.take_message_from_outbound()
    }

    fn add_agent(&mut self, agent: Agent) -> AgentName {
        let name = agent.name;
        self.agents.push(agent);
        name
    }

    pub fn new_agent(&mut self, descriptor: &AgentDescriptor) -> Result<AgentName, Error> {
        let agent_name = self.add_agent(Agent::new(self, descriptor)?);
        Ok(agent_name)
    }

    fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent, Error> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.name == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            ))
        })
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent, Error> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.name == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {}. Did you forget to call spawn_agents?",
                name
            ))
        })
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
}

#[derive(Clone, Deserialize, Serialize, Hash)]
pub struct Trace {
    pub descriptors: Vec<AgentDescriptor>,
    pub steps: Vec<Step>,
    pub prior_traces: Vec<Trace>,
}

/// A [`Trace`] consists of several [`Step`]s. Each has either a [`OutputAction`] or an [`InputAction`].
/// Each [`Step`]s references an [`Agent`] by name. Furthermore, a trace also has a list of
/// *AgentDescriptors* which act like a blueprint to spawn [`Agent`]s with a corresponding server
/// or client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
impl Trace {
    fn spawn_agents(&self, ctx: &mut TraceContext) -> Result<(), Error> {
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

    pub fn execute(&self, ctx: &mut TraceContext) -> Result<(), Error> {
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
                    let output_step = &Step {
                        agent: step.agent,
                        action: Action::Output(OutputAction {}),
                    };

                    output_step.action.execute(output_step, ctx)?;
                }
                Action::Output(_) => {}
            }

            ctx.claims.deref_borrow().log();
        }

        let claims = ctx.claims.deref_borrow();
        if let Some(msg) = claims.check_violation(Policy { func: is_violation }) {
            // [TODO] versus checking at each step ? Could detect violation earlier, before a blocking state is reached ? [BENCH] benchmark the efficiency loss of doing so
            return Err(Error::SecurityClaim(msg, claims.clone()));
        }

        Ok(())
    }

    pub fn execute_default(&self) -> TraceContext {
        let mut ctx = TraceContext::new();
        self.execute(&mut ctx).unwrap();
        ctx
    }
}

impl fmt::Debug for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trace with {} steps", self.steps.len())
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Trace:")?;
        for step in &self.steps {
            write!(f, "\n{} -> {}", step.agent, step.action)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
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
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
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
pub struct OutputAction {}

impl OutputAction {
    pub fn new_step(agent: AgentName) -> Step {
        Step {
            agent,
            action: Action::Output(OutputAction {}),
        }
    }

    fn output(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), Error> {
        ctx.next_state(step.agent)?;

        while let Some(MessageResult(message_o, opaque_message)) =
            ctx.take_message_from_outbound(step.agent)?
        {
            let message_result = MessageResult(message_o, opaque_message);
            let MessageResult(message, opaque_message) = &message_result;
            let tls_message_type = Some(TlsMessageType::try_from(&message_result)?);

            match &message {
                Some(message) => {
                    let knowledge = extract_knowledge(message)?;

                    debug!("Knowledge increased by {:?}", knowledge.len() + 1); // +1 because of the OpaqueMessage below

                    for variable in knowledge {
                        let data_type_id = variable.as_ref().type_id();

                        let counter =
                            ctx.number_matching_message(step.agent, data_type_id, tls_message_type);
                        let knowledge = Knowledge {
                            agent_name: step.agent,
                            tls_message_type,
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
            let knowledge = Knowledge {
                agent_name: step.agent,
                tls_message_type: None, // none because we can not trust the decoding of tls_message_type, because the message could be encrypted like in TLS 1.2
                data: Box::new(message_result.1),
            };

            let counter = ctx.number_matching_message(step.agent, type_id, None);
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

impl fmt::Display for OutputAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputAction")
    }
}

/// The [`InputAction`] evaluates the recipe term and injects the newly produced message
/// into the *inbound channel* of the [`Agent`] referenced through the corresponding [`Step`]s
/// by calling `add_to_inbound(...)` and then drives the state machine forward.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
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
            debug_message_with_info("Input message".to_string().as_str(), msg);

            let opaque_message = PlainMessage::from(msg.clone()).into_unencrypted_opaque();
            ctx.add_to_inbound(step.agent, &opaque_message)?;
        } else if let Some(opaque_message) = evaluated.as_ref().downcast_ref::<OpaqueMessage>() {
            debug_opaque_message_with_info(
                "Input opaque message".to_string().as_str(),
                opaque_message,
            );
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

impl fmt::Display for InputAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputAction:\n{}", self.recipe)
    }
}
