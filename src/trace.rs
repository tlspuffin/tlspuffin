use core::fmt;
use std::any::{Any, TypeId};
use std::fmt::Formatter;

use rustls::internal::msgs::enums::Compression;
use rustls::internal::msgs::handshake::{ClientExtension, HandshakePayload, Random, SessionID};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::{CipherSuite, ProtocolVersion};

use crate::agent::{Agent, AgentName};
#[allow(unused)] // used in docs
use crate::io::Channel;
use crate::term::{op_client_hello, Signature, Term};
use crate::variable_data::{AsAny, VariableData, extract_variables};

pub struct TraceContext {
    /// The knowledge of the attacker
    knowledge: Vec<Box<dyn VariableData>>,
    agents: Vec<Agent>,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            knowledge: vec![],
            agents: vec![],
        }
    }

    pub fn add_variable(&mut self, variable: Box<dyn VariableData>) {
        self.knowledge.push(variable)
    }

    pub fn add_variables<I>(&mut self, variables: I)
    where
        I: IntoIterator<Item = Box<dyn VariableData>>,
    {
        for variable in variables {
            self.add_variable(variable)
        }
    }

    // Why do we need to extend Any here? do we need to make sure that the types T are known during
    // compile time?
    fn downcast<T: Any>(variable: &dyn AsRef<dyn VariableData>) -> Option<&T> {
        variable.as_ref().as_any().downcast_ref::<T>()
    }

    pub fn get_variable<T: VariableData + 'static>(&self) -> Option<&T> {
        // todo handle if multiple variable are found
        for variable in &self.knowledge {
            if let Some(derived) = TraceContext::downcast(variable) {
                return Some(derived);
            }
        }
        None
    }

    pub fn get_variable_by_type_id(
        &self,
        type_id: TypeId,
    ) -> Option<&(dyn VariableData + 'static)> {
        // todo handle if multiple variable are found
        for data in &self.knowledge {
            if type_id == data.as_ref().as_any().type_id() {
                return Some(data.as_ref());
            }
        }
        None
    }

    pub fn get_variable_set<T: VariableData + 'static>(&self) -> Vec<&T> {
        let mut variables: Vec<&T> = Vec::new();
        for variable in &self.knowledge {
            if let Some(derived) = TraceContext::downcast(variable) {
                variables.push(derived);
            }
        }
        variables
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
        self.agents.push(agent);
        return name;
    }

    pub fn new_agent(&mut self) -> AgentName {
        return self.add_agent(Agent::new());
    }

    pub fn new_openssl_agent(&mut self, server: bool) -> AgentName {
        return self.add_agent(Agent::new_openssl(server));
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

pub struct Trace {
    pub steps: Vec<Step>,
}

impl Trace {
    pub fn execute(&mut self, ctx: &mut TraceContext) {
        self.execute_with_listener(ctx, |step| {})
    }

    pub fn execute_with_listener(
        &mut self,
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

pub struct Step {
    pub agent: AgentName,
    pub action: Action,
}

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

pub struct OutputAction;

impl OutputAction {
    fn output(&self, step: &Step, ctx: &mut TraceContext) {
        if let Err(_) = ctx.next_state(step.agent) {
            panic!("Failed to go to next state!")
        }
        while let Ok(message) = ctx.take_message_from_outbound(step.agent) {
            let knowledge = extract_variables(&message);
            ctx.add_variables(knowledge);
        }
    }
}

pub struct InputAction {
    pub recipe: Term
}

impl InputAction {
    fn input(&self, step: &Step, ctx: &mut TraceContext) {
        // message controlled by the attacker
        let x = self.recipe
            .evaluate(ctx)
            .unwrap();
        let attacker_message = x.as_ref()
            .downcast_ref::<Message>()
            .unwrap(); // todo return errors

        //let attacker_message = Message::build_key_update_notify();

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
