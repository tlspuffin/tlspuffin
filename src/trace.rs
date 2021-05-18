use core::fmt;
use std::any::Any;
use std::fmt::Formatter;

use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;

use crate::agent::{Agent, AgentName};
#[allow(unused)] // used in docs
use crate::io::Channel;
use rustls::internal::msgs::handshake::HandshakePayload;
use crate::variable_data::VariableData;


pub struct TraceContext {
    variables: Vec<Box<dyn VariableData>>,
    agents: Vec<Agent>,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            variables: vec![],
            agents: vec![],
        }
    }

    pub fn add_variable(&mut self, variable: Box<dyn VariableData>) {
        self.variables.push(variable)
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

    pub fn get_variable<T: Any>(&self, agent: AgentName) -> Option<&T> {
        for variable in &self.variables {
            if variable.get_metadata().owner != agent {
                continue;
            }

            if let Some(derived) = TraceContext::downcast(variable) {
                return Some(derived);
            }
        }
        None
    }

    pub fn get_variable_set<T: Any>(&self, agent: AgentName) -> Vec<&T> {
        let mut variables: Vec<&T> = Vec::new();
        for variable in &self.variables {
            if variable.get_metadata().owner != agent {
                continue;
            }

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

            if i != steps.len() - 1 {
                // TODO do not skip the last one, handle if no next
                let result = ctx.take_message_from_outbound(step.agent).unwrap();
                // TODO send_to no longer exists
                // ctx.add_to_inbound(step.send_to, &result);
            }

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
                input.receive(step, ctx);
            },
            Action::Output(output) => {
                output.craft(ctx, step.agent);
            },
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
pub struct InputAction;

impl OutputAction {
    fn craft(&self, ctx: &TraceContext, agent: AgentName) -> Result<Message, ()> {
        Ok(Message::build_key_update_notify())
    }
}

impl InputAction {
    fn receive(&self, step: &Step, ctx: &mut TraceContext) {}
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
