use core::fmt;
use std::any::TypeId;
use std::cell::RefCell;
use std::fmt::Formatter;
use std::rc::Rc;

use libafl::bolts::ownedref::OwnedSlice;
use libafl::inputs::{HasBytesVec, HasLen, HasTargetBytes, Input};
use rustls::internal::msgs::handshake::HandshakePayload;
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::agent::{Agent, AgentName};
#[allow(unused)] // used in docs
use crate::io::Channel;
use crate::term::Term;
use crate::term::TypeShape;
use crate::variable_data::{extract_variables, VariableData};

pub type ObservedId = (u16, u16);

struct ObservedVariable {
    observed_id: ObservedId,
    data: Box<dyn VariableData>,
}

pub struct TraceContext {
    /// The knowledge of the attacker
    knowledge: Vec<ObservedVariable>,
    agents: Vec<Agent>,
    last_agent_added: AgentName,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            knowledge: vec![],
            agents: vec![],
            last_agent_added: AgentName::none(),
        }
    }

    pub fn add_variable(&mut self, observed_id: ObservedId, data: Box<dyn VariableData>) {
        self.knowledge.push(ObservedVariable { observed_id, data })
    }

    pub fn add_variables<I>(&mut self, observed_id: ObservedId, variables: I)
    where
        I: IntoIterator<Item = Box<dyn VariableData>>,
    {
        for variable in variables {
            self.add_variable(observed_id, variable)
        }
    }

    pub fn get_variable_by_type_id(
        &self,
        type_shape: TypeShape,
        observed_id: ObservedId,
    ) -> Option<&(dyn VariableData + 'static)> {
        let type_id: TypeId = type_shape.into();

        for observed in &self.knowledge {
            let data: &dyn VariableData = observed.data.as_ref();
            if type_id == data.as_any().type_id() && observed_id == observed.observed_id {
                return Some(data);
            }
        }
        None
    }

    /// Adds data to the inbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    pub fn add_to_inbound(
        &mut self,
        agent_name: AgentName,
        message: &Message,
    ) -> Result<(), String> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.add_to_inbound(message))
    }

    pub fn next_state(&mut self, agent_name: AgentName) -> Result<(), String> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.next_state())
    }

    /// Takes data from the outbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    /// See [`MemoryStream::take_message_from_outbound`]
    pub fn take_message_from_outbound(&mut self, agent_name: AgentName) -> Result<Message, String> {
        self.find_agent_mut(agent_name).and_then(|agent| {
            agent
                .stream
                .take_message_from_outbound()
                .ok_or::<String>("Failed to take data from inbound channel".to_string())
        })
    }

    fn add_to_outbound(
        &mut self,
        agent_name: AgentName,
        message: &Message,
        prepend: bool,
    ) -> Result<(), String> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.add_to_outbound(message, prepend))
    }

    pub fn take_from_inbound(&mut self, agent_name: AgentName) -> Result<Message, String> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.take_from_inbound().unwrap())
    }

    fn add_agent(&mut self, agent: Agent) -> AgentName {
        let name = agent.name;
        self.last_agent_added = agent.name;
        self.agents.push(agent);
        return name;
    }

    pub fn new_openssl_agent(&mut self, server: bool) -> AgentName {
        return self.add_agent(Agent::new_openssl(&self.last_agent_added, server));
    }

    fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent, String> {
        if name == AgentName::none() {
            panic!("None Agent does not exist")
        }

        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.name == name)
            .ok_or(format!("Could not find agent {}", name))
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent, String> {
        if name == AgentName::none() {
            panic!("None Agent does not exist")
        }

        let mut iter = self.agents.iter();
        iter.find(|agent| agent.name == name)
            .ok_or(format!("Could not find agent {}", name))
    }
}

#[derive(Debug)]
pub struct Trace {
    pub steps: Vec<Step>,
}

impl Clone for Trace {
    fn clone(&self) -> Trace {
        Trace { steps: vec![] }
    }
}

impl<'de> Deserialize<'de> for Trace {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Trace { steps: vec![] })
    }
}
impl Serialize for Trace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Trace", 0)?;
        s.end()
    }
}

// LibAFL support
impl Input for Trace {}

impl HasLen for Trace {
    fn len(&self) -> usize {
        self.steps.len()
    }
}

impl Trace {
    pub fn execute(&self, ctx: &mut TraceContext) {
        self.execute_with_listener(ctx, |step| {})
    }

    pub fn execute_with_listener(
        &self,
        ctx: &mut TraceContext,
        execution_listener: fn(step: &Step) -> (),
    ) {
        let steps = &self.steps;
        for i in 0..steps.len() {
            let step = &steps[i];
            step.action.execute(step, ctx);
            execution_listener(step);
        }
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Action {
    Input(InputAction),
    Output(OutputAction),
}

pub trait Execute: fmt::Display {
    fn execute(&self, step: &Step, ctx: &mut TraceContext);
}

impl Execute for Action {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) {
        match self {
            Action::Input(input) => {
                input.input(step, ctx);
            }
            Action::Output(output) => {
                output.output(step, ctx);
            }
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Action::Input(_) => "Input",
                Action::Output(_) => "Output",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OutputAction {
    pub id: u16,
}

impl OutputAction {
    fn output(&self, step: &Step, ctx: &mut TraceContext) {
        if let Err(_) = ctx.next_state(step.agent) {
            panic!("Failed to go to next state!")
        }
        let mut sub_id = 0u16;
        while let Ok(message) = ctx.take_message_from_outbound(step.agent) {
            let knowledge = extract_variables(&message);
            ctx.add_variables((self.id, sub_id), knowledge);
            sub_id += 1;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InputAction {
    pub recipe: Term,
}

impl InputAction {
    fn input(&self, step: &Step, ctx: &mut TraceContext) {
        // message controlled by the attacker
        let x = self.recipe.evaluate(ctx).unwrap();
        let attacker_message = x.as_ref().downcast_ref::<Message>().unwrap(); // todo return errors

        if let Err(_) = ctx.add_to_inbound(step.agent, &attacker_message) {
            panic!("Failed to insert term to agents inbound channel!")
        }

        if let Err(_) = ctx.next_state(step.agent) {
            panic!("Failed to go to next state!")
        }
    }
}

// parsing utils

pub fn take_handshake_payload(step: &Step, ctx: &mut TraceContext) -> Option<HandshakePayload> {
    // todo, we are creating variables only from the message in the oubound buffer, but the reeiver
    // // of a message also has access to the message in the inbound
    match ctx.take_from_inbound(step.agent) {
        // reads internally from inbound of agent
        Ok(message) => match message.payload {
            Handshake(payload) => Some(payload.payload),
            _ => None,
        },
        Err(msg) => {
            panic!("{}", msg)
        }
    }
}
