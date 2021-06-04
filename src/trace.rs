use core::fmt;
use std::{any::TypeId, fmt::Formatter};

use libafl::inputs::{HasLen, Input};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::OpaqueMessage;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::agent::{TLSVersion, AgentDescriptor};
use crate::debug::{debug_message_with_info, debug_opaque_message_with_info};
#[allow(unused)] // used in docs
use crate::io::Channel;
use crate::io::MessageResult;
use crate::tls::{MultiMessage};
use crate::{
    agent::{Agent, AgentName},
    term::{Term, TypeShape},
    variable_data::{extract_variables, VariableData},
};

pub type ObservedId = (u16, u16);

struct ObservedVariable {
    observed_id: ObservedId,
    data: Box<dyn VariableData>,
}

pub struct TraceContext {
    /// The knowledge of the attacker
    knowledge: Vec<ObservedVariable>,
    agents: Vec<Agent>,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            knowledge: vec![],
            agents: vec![]
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
        message: &MessageResult,
    ) -> Result<(), String> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.add_to_inbound(message))
    }

    pub fn next_state(&mut self, agent_name: AgentName) -> Result<(), String> {
        self.find_agent_mut(agent_name)
            .map(|agent| agent.stream.next_state())?
    }

    /// Takes data from the outbound [`Channel`] of the [`Agent`] referenced by the parameter "agent".
    /// See [`MemoryStream::take_message_from_outbound`]
    pub fn take_message_from_outbound(
        &mut self,
        agent_name: AgentName,
    ) -> Result<MessageResult, String> {
        self.find_agent_mut(agent_name).and_then(|agent| {
            agent
                .stream
                .take_message_from_outbound()
                .ok_or::<String>("Failed to take data from inbound channel".to_string())
        })
    }

    fn add_agent(&mut self, agent: Agent) -> AgentName {
        let name = agent.descriptor.name;
        self.agents.push(agent);
        return name;
    }

    pub fn new_openssl_agent(
        &mut self,
        descriptor: &AgentDescriptor,
    ) -> AgentName {
        return self.add_agent(Agent::new_openssl(descriptor));
    }

    fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent, String> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.descriptor.name == name).ok_or(format!(
            "Could not find agent {}. Did you forget to call spawn_agents?",
            name
        ))
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent, String> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.descriptor.name == name).ok_or(format!(
            "Could not find agent {}. Did you forget to call spawn_agents?",
            name
        ))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Trace {
    pub descriptors: Vec<AgentDescriptor>,
    pub steps: Vec<Step>,
}

// LibAFL support
impl Input for Trace {}

impl HasLen for Trace {
    fn len(&self) -> usize {
        self.steps.len()
    }
}

impl Trace {
    pub fn spawn_agents(&self, ctx: &mut TraceContext) {
        for descriptor in &self.descriptors {
            ctx.new_openssl_agent(&descriptor);
        }
    }

    pub fn execute(&self, ctx: &mut TraceContext) -> Result<(), String> {
        self.execute_with_listener(ctx, |_step| {})
    }

    pub fn execute_with_listener(
        &self,
        ctx: &mut TraceContext,
        execution_listener: fn(step: &Step) -> (),
    ) -> Result<(), String> {
        let steps = &self.steps;
        for i in 0..steps.len() {
            let step = &steps[i];
            if let Err(err) = step.action.execute(step, ctx) {
                return Err(err);
            }

            execution_listener(step);
        }

        Ok(())
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

pub trait Execute {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), String>;
}

impl Execute for Action {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), String> {
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OutputAction {
    pub id: u16,
}

impl OutputAction {
    fn output(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), String> {
        ctx.next_state(step.agent)?;

        let mut sub_id = 0u16;
        while let Ok(result) = ctx.take_message_from_outbound(step.agent) {
            match result {
                MessageResult::Message(message) => {
                    debug_message_with_info(
                        format!("Output message with observed id {:?}", (self.id, sub_id)).as_str(),
                        &message,
                    );
                    let knowledge = extract_variables(&message);
                    info!("New knowledge: {:?}", knowledge.len());
                    ctx.add_variables((self.id, sub_id), knowledge);
                }
                MessageResult::OpaqueMessage(opaque_message) => {
                    // The finish Message in TLS1.2 can not be parsed to a rustls Message as it is
                    // encrypted. We need tow ork with the opaque type in this case
                    debug_opaque_message_with_info(
                        format!(
                            "Output opaque message with observed id {:?}",
                            (self.id, sub_id)
                        )
                        .as_str(),
                        &opaque_message,
                    );
                    ctx.add_variable((self.id, sub_id), Box::new(opaque_message.payload.0));
                }
            }

            sub_id += 1;
        }
        Ok(())
    }
}

impl fmt::Display for OutputAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "OutputAction")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InputAction {
    pub recipe: Term,
}

/// Processes messages in the inbound channel. Uses the recipe field to evaluate to a rustls Message
/// or a MultiMessage.
impl InputAction {
    fn input(&self, step: &Step, ctx: &mut TraceContext) -> Result<(), String> {
        // message controlled by the attacker
        let evaluated = self
            .recipe
            .evaluate(ctx)
            .map_err(|err| format!("{}", err))?;

        if let Some(msg) = evaluated.as_ref().downcast_ref::<Message>() {
            ctx.add_to_inbound(step.agent, &MessageResult::Message(msg.clone()))?;

            debug_message_with_info(format!("Input message").as_str(), msg);
        } else if let Some(multi) = evaluated.as_ref().downcast_ref::<MultiMessage>() {
            for msg in &multi.messages {
                ctx.add_to_inbound(step.agent, &MessageResult::Message(msg.clone()))?;
                debug_message_with_info(format!("Input message").as_str(), msg);
            }
        } else if let Some(opaque_message) = evaluated.as_ref().downcast_ref::<OpaqueMessage>() {
            ctx.add_to_inbound(
                step.agent,
                &MessageResult::OpaqueMessage(opaque_message.clone()),
            )?;

            debug_opaque_message_with_info(
                format!("Input opaque message").as_str(),
                opaque_message,
            );
        } else {
            return Err(String::from("Recipe is not a `Message`, `OpaqueMessage` or `MultiMessage`!"));
        }

        ctx.next_state(step.agent)
    }
}

impl fmt::Display for InputAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "recipe: {}", self.recipe)
    }
}
