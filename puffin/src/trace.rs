//! This module define the execution [`Trace`]s.
//!
//! Each [`Trace`]s consist of several [`Step`]s, of which each has either an [`OutputAction`] or
//! [`InputAction`]. This is a declarative way of modeling communication between [`Agent`]s. The
//! [`TraceContext`] holds data, also known as [`Knowledge`], which is created by [`Agent`]s
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
use std::any::TypeId;
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
use crate::claims::{GlobalClaimList, SecurityViolationPolicy};
use crate::error::Error;
use crate::protocol::{EvaluatedTerm, ProtocolBehavior, ProtocolTypes};
use crate::put::PutDescriptor;
use crate::put_registry::PutRegistry;
use crate::stream::Stream;
use crate::trace::Action::Input;

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
    Label(Option<String>),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Agent(x) => write!(f, "agent:{x}"),
            Self::Label(x) => write!(f, "label:{x:?}"),
        }
    }
}

/// [Knowledge] describes an atomic piece of knowledge inferred by the
/// [`crate::protocol::Extractable::extract_knowledge`] function
/// [Knowledge] is made of the data, the source of the output, the
/// TLS message type and the internal type.
#[derive(Debug)]
pub struct Knowledge<'a, PT: ProtocolTypes> {
    pub source: &'a Source,
    pub matcher: Option<PT::Matcher>,
    pub data: &'a dyn EvaluatedTerm<PT>,
}

/// [`RawKnowledge`] stores
#[derive(Debug)]
pub struct RawKnowledge<PT: ProtocolTypes> {
    pub source: Source,
    pub matcher: Option<PT::Matcher>,
    pub associated_term: Option<Term<PT>>,
    pub data: Box<dyn EvaluatedTerm<PT>>,
}

impl<PT: ProtocolTypes> fmt::Display for RawKnowledge<PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

impl<'a, PT: ProtocolTypes> IntoIterator for &'a RawKnowledge<PT> {
    type IntoIter = IntoIter<Knowledge<'a, PT>>;
    type Item = Knowledge<'a, PT>;

    fn into_iter(self) -> Self::IntoIter {
        let mut knowledges = vec![];
        let _ = self
            .data
            .extract_knowledge(&mut knowledges, self.matcher.clone(), &self.source);
        knowledges.into_iter()
    }
}

impl<PT: ProtocolTypes> Knowledge<'_, PT> {
    pub fn specificity(&self) -> u32 {
        self.matcher.specificity()
    }
}

impl<PT: ProtocolTypes> Knowledge<'_, PT> {
    pub fn debug_print<PB>(&self, ctx: &TraceContext<PB>, source: &Source)
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
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

impl<PT: ProtocolTypes> fmt::Display for Knowledge<'_, PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})/{:?}", self.source, self.matcher)
    }
}

#[derive(Debug, Default)]
pub struct KnowledgeStore<PT: ProtocolTypes> {
    raw_knowledge: Vec<RawKnowledge<PT>>,
}

impl<PT: ProtocolTypes> KnowledgeStore<PT> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            raw_knowledge: vec![],
        }
    }

    pub fn add_raw_knowledge<T: EvaluatedTerm<PT> + 'static>(
        &mut self,
        data: T,
        source: Source,
        term: Option<Term<PT>>,
    ) {
        log::trace!("Adding raw knowledge for {:?}", &data);

        self.raw_knowledge.push(RawKnowledge {
            source,
            matcher: None,
            data: Box::new(data),
            associated_term: term,
        });
    }

    pub fn add_raw_boxed_knowledge(
        &mut self,
        data: Box<dyn EvaluatedTerm<PT>>,
        source: Source,
        term: Option<Term<PT>>,
    ) {
        log::trace!("Adding raw knowledge : {:?}", &data);

        self.raw_knowledge.push(RawKnowledge {
            source,
            matcher: None,
            data,
            associated_term: term,
        });
    }

    pub fn number_matching_message_with_source(
        &self,
        source: Source,
        type_id: TypeId,
        tls_message_type: &Option<PT::Matcher>,
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
        tls_message_type: &Option<PT::Matcher>,
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
        query_type_shape: TypeShape<PT>,
        query: &Query<PT::Matcher>,
    ) -> Option<&(dyn EvaluatedTerm<PT>)> {
        let query_type_id: TypeId = query_type_shape.into();

        let mut possibilities: Vec<Knowledge<PT>> = self
            .raw_knowledge
            .iter()
            .filter(|raw| (query.source.is_none() || query.source.as_ref().unwrap() == &raw.source))
            .flatten()
            .filter(|knowledge| {
                query_type_id == knowledge.data.type_id()
                    && knowledge.matcher.matches(&query.matcher)
            })
            .collect();

        possibilities.sort_by_key(Knowledge::specificity);

        possibilities
            .get(query.counter as usize)
            .map(|possibility| possibility.data)
    }
}

#[derive(Debug)]
pub struct Spawner<PB: ProtocolBehavior> {
    registry: PutRegistry<PB>,
    descriptors: HashMap<AgentName, PutDescriptor>,
    default: PutDescriptor,
}

impl<PB: ProtocolBehavior> Spawner<PB> {
    pub fn new(registry: impl Into<PutRegistry<PB>>) -> Self {
        let registry = registry.into();
        Self {
            default: registry.default().name().into(),
            registry,
            descriptors: Default::default(),
        }
    }

    #[must_use]
    pub fn with_mapping(mut self, descriptors: &[(AgentName, PutDescriptor)]) -> Self {
        self.descriptors.extend(descriptors.iter().cloned());
        self
    }

    pub fn with_default(mut self, put: impl Into<PutDescriptor>) -> Self {
        self.default = put.into();
        self
    }

    pub fn spawn(
        &self,
        claims: &GlobalClaimList<PB::ProtocolTypes, PB::Claim>,
        descriptor: &AgentDescriptor,
    ) -> Result<Agent<PB>, Error> {
        let put_descriptor = self
            .descriptors
            .get(&descriptor.name)
            .cloned()
            .unwrap_or_else(|| self.default.clone());

        let factory = self
            .registry
            .find_by_id(&put_descriptor.factory)
            .ok_or_else(|| {
                Error::Agent(format!(
                    "unable to find PUT {} factory in binary",
                    &put_descriptor.factory
                ))
            })?;

        let put = factory.create(descriptor, claims, &put_descriptor.options)?;
        Ok(Agent::new(descriptor.clone(), put))
    }
}

impl<PB: ProtocolBehavior + PartialEq> PartialEq for Spawner<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.registry == other.registry
            && self.descriptors == other.descriptors
            && self.default == other.default
    }
}

impl<PB: ProtocolBehavior> Clone for Spawner<PB> {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            descriptors: self.descriptors.clone(),
            default: self.default.clone(),
        }
    }
}

/// The [`TraceContext`] represents the state of an execution.
///
/// The [`TraceContext`] contains a list of [`EvaluatedTerm`], which is known as the knowledge
/// of the attacker. [`EvaluatedTerm`] can contain data of various types like for example
/// client and server extensions, cipher suits or session ID It also holds the concrete
/// references to the [`Agent`]s and the underlying streams, which contain the messages
/// which have need exchanged and are not yet processed by an output step.
#[derive(Debug)]
pub struct TraceContext<PB: ProtocolBehavior> {
    /// The knowledge of the attacker
    pub knowledge_store: KnowledgeStore<PB::ProtocolTypes>,
    agents: Vec<Agent<PB>>,
    claims: GlobalClaimList<PB::ProtocolTypes, PB::Claim>,

    spawner: Spawner<PB>,

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
            write!(f, "\n   {k},          --  {k:?}")?;
        }
        Ok(())
    }
}

impl<PB: ProtocolBehavior + PartialEq> PartialEq for TraceContext<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.agents == other.agents
            && self.spawner == other.spawner
            && format!("{:?}", self.knowledge_store.raw_knowledge)
                == format!("{:?}", other.knowledge_store.raw_knowledge)
            && format!("{:?}", self.claims) == format!("{:?}", other.claims)
    }
}

impl<PB: ProtocolBehavior> TraceContext<PB> {
    #[must_use]
    pub fn new(spawner: Spawner<PB>) -> Self {
        // We keep a global list of all claims throughout the execution. Each claim is identified
        // by the AgentName. A rename of an Agent does not interfere with this.
        let claims = GlobalClaimList::new();

        Self {
            knowledge_store: KnowledgeStore::new(),
            agents: vec![],
            claims,
            spawner,
            phantom: Default::default(),
        }
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
        tls_message_type: &Option<<PB::ProtocolTypes as ProtocolTypes>::Matcher>,
    ) -> usize {
        self.knowledge_store
            .number_matching_message_with_source(source, type_id, tls_message_type)
    }

    /// Count the number of sub-messages of type `type_id` in the output message.
    pub fn number_matching_message(
        &self,
        type_id: TypeId,
        tls_message_type: &Option<<PB::ProtocolTypes as ProtocolTypes>::Matcher>,
    ) -> usize {
        self.knowledge_store
            .number_matching_message(type_id, tls_message_type)
    }

    #[must_use]
    pub fn find_claim(
        &self,
        agent_name: AgentName,
        query_type_shape: TypeShape<PB::ProtocolTypes>,
    ) -> Option<Box<dyn EvaluatedTerm<PB::ProtocolTypes>>> {
        self.claims
            .deref_borrow()
            .find_last_claim(agent_name, query_type_shape)
            .map(super::claims::Claim::inner)
    }

    /// Returns the variable which matches best -> highest specificity
    /// If we want a variable with lower specificity, then we can just query less specific
    pub fn find_variable(
        &self,
        query_type_shape: TypeShape<PB::ProtocolTypes>,
        query: &Query<<PB::ProtocolTypes as ProtocolTypes>::Matcher>,
    ) -> Option<&(dyn EvaluatedTerm<PB::ProtocolTypes>)> {
        self.knowledge_store.find_variable(query_type_shape, query)
    }

    pub fn spawn(&mut self, descriptor: &AgentDescriptor) -> Result<(), Error> {
        let agent = self.spawner.spawn(&self.claims, descriptor)?;
        self.agents.push(agent);

        Ok(())
    }

    pub fn find_agent_mut(&mut self, name: AgentName) -> Result<&mut Agent<PB>, Error> {
        let mut iter = self.agents.iter_mut();

        iter.find(|agent| agent.name() == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {name}. Did you forget to call spawn_agents?"
            ))
        })
    }

    pub fn find_agent(&self, name: AgentName) -> Result<&Agent<PB>, Error> {
        let mut iter = self.agents.iter();
        iter.find(|agent| agent.name() == name).ok_or_else(|| {
            Error::Agent(format!(
                "Could not find agent {name}. Did you forget to call spawn_agents?"
            ))
        })
    }

    #[must_use]
    pub fn agents_successful(&self) -> bool {
        self.agents
            .iter()
            .all(super::agent::Agent::is_state_successful)
    }
}

#[derive(Clone, Deserialize, Serialize, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Trace<PT: ProtocolTypes> {
    pub descriptors: Vec<AgentDescriptor>,
    pub steps: Vec<Step<PT>>,
    pub prior_traces: Vec<Trace<PT>>,
}

/// A [`Trace`] consists of several [`Step`]s. Each has either a [`OutputAction`] or an
/// [`InputAction`]. Each [`Step`]s references an [`Agent`] by name. Furthermore, a trace also has a
/// list of *`AgentDescriptors`* which act like a blueprint to spawn [`Agent`]s with a corresponding
/// server or client role and a specific TLs version. Essentially they are an [`Agent`] without a
/// stream.
impl<PT: ProtocolTypes> Trace<PT> {
    pub fn spawn_agents<PB: ProtocolBehavior>(
        &self,
        ctx: &mut TraceContext<PB>,
    ) -> Result<(), Error> {
        for descriptor in &self.descriptors {
            if let Some(reusable) = ctx
                .agents
                .iter_mut()
                .find(|existing| existing.is_reusable_with(descriptor))
            {
                // rename if it already exists and we want to reuse
                reusable.reset(descriptor.name)?;
            } else {
                // only spawn completely new if not yet existing
                ctx.spawn(descriptor)?;
            };
        }

        Ok(())
    }

    pub fn execute_until_step<PB>(
        &self,
        ctx: &mut TraceContext<PB>,
        nb_steps: usize,
    ) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        for trace in &self.prior_traces {
            trace.execute(ctx)?;
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
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        self.execute_until_step(ctx, self.steps.len())
    }

    pub fn serialize_postcard(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(&self)
    }

    pub fn deserialize_postcard(slice: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes::<Self>(slice)
    }

    #[must_use]
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

    #[must_use]
    pub fn is_symbolic(&self) -> bool {
        self.steps.iter().all(|e| match &e.action {
            Input(r) => r.recipe.is_symbolic(),
            _ => true,
        })
    }
}

impl<PT: ProtocolTypes> fmt::Debug for Trace<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trace with {} steps", self.steps.len())
    }
}

impl<PT: ProtocolTypes> fmt::Display for Trace<PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Trace:")?;
        for step in &self.steps {
            write!(f, "\n{} -> {}", step.agent, step.action)?;
        }
        Ok(())
    }
}

impl<PT: ProtocolTypes> AsRef<Self> for Trace<PT> {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Step<PT: ProtocolTypes> {
    pub agent: AgentName,
    pub action: Action<PT>,
}

impl<PT: ProtocolTypes> Step<PT> {
    pub fn execute<PB>(&self, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        match &self.action {
            Action::Input(input) => input.execute(self.agent, ctx).and_then(|()| {
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
#[serde(bound = "PT: ProtocolTypes")]
pub enum Action<PT: ProtocolTypes> {
    Input(InputAction<PT>),
    Output(OutputAction<PT>),
}

impl<PT: ProtocolTypes> fmt::Display for Action<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(input) => write!(f, "{input}"),
            Self::Output(output) => write!(f, "{output}"),
        }
    }
}

/// Advance the [`Agent`]'s state and process the produced output.
///
/// The [`OutputAction`] first forwards the state machine and then extracts knowledge from the TLS
/// messages produced by the underlying stream by calling  `take_message_from_outbound(...)`. An
/// output action is automatically called after each input step.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct OutputAction<PT> {
    phantom: PhantomData<PT>,
}

impl<PT: ProtocolTypes> OutputAction<PT> {
    #[must_use]
    pub fn new_step(agent: AgentName) -> Step<PT> {
        Step {
            agent,
            action: Action::Output(Self {
                phantom: Default::default(),
            }),
        }
    }

    fn execute<PB>(&self, agent_name: AgentName, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        let source = Source::Agent(agent_name);
        let agent = ctx.find_agent_mut(agent_name)?;

        agent.progress()?;

        if let Some(opaque_flight) = agent.take_message_from_outbound()? {
            ctx.knowledge_store
                .add_raw_knowledge(opaque_flight.clone(), source.clone(), None);

            if let Ok(flight) = TryInto::<PB::ProtocolMessageFlight>::try_into(opaque_flight) {
                ctx.knowledge_store.add_raw_knowledge(flight, source, None);
            }
        }

        Ok(())
    }
}

impl<PT: ProtocolTypes> fmt::Display for OutputAction<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputAction")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Precomputation<PT: ProtocolTypes> {
    pub label: Option<String>,
    pub recipe: Term<PT>,
}

/// Provide inputs to the [`Agent`].
///
/// The [`InputAction`] evaluates the recipe term and injects the newly produced message
/// into the *inbound channel* of the [`Agent`] referenced through the corresponding [`Step`]s
/// by calling `add_to_inbound(...)` and then drives the state machine forward.
#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct InputAction<PT: ProtocolTypes> {
    pub precomputations: Vec<Precomputation<PT>>,
    pub recipe: Term<PT>,
}

/// Processes messages in the inbound channel. Uses the recipe field to evaluate to a rustls Message
/// or a `MultiMessage`.
impl<PT: ProtocolTypes> InputAction<PT> {
    pub const fn new_step(agent: AgentName, recipe: Term<PT>) -> Step<PT> {
        Step {
            agent,
            action: Action::Input(Self {
                recipe,
                precomputations: vec![],
            }),
        }
    }

    fn execute<PB>(&self, agent_name: AgentName, ctx: &mut TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        for precomputation in &self.precomputations {
            let eval = precomputation.recipe.evaluate_DY(ctx)?; // We do not accept payloads in recipes
            ctx.knowledge_store.add_raw_boxed_knowledge(
                eval,
                Source::Label(precomputation.label.clone()),
                Some(precomputation.recipe.clone()),
            );
        }

        let message = self.recipe.evaluate_DY(ctx)?;
        let agent = ctx.find_agent_mut(agent_name)?;
        let message = message.get_encoding();
        agent.add_to_inbound(&message);
        agent.progress()
    }
}

impl<PT: ProtocolTypes> fmt::Display for InputAction<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InputAction:\n{}", self.recipe)
    }
}

/// This macro defines the precomputation syntax to add precomputations to an input action step
///
/// Example of precomputation with TLS
///
/// ```ignore
/// input_action! {
///     // Here we are precomputing a decryption of TLS extension and using it in the following term
///     "decrypted_extensions" = term!{fn_decrypt_handshake_flight(
///         ((server, 0)/MessageFlight),
///         (@server_hello_transcript),
///         (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
///         fn_no_psk,
///         fn_named_group_secp384r1,
///         fn_true,
///         fn_seq_0  // sequence 0
///     )}
///     =>
///     // This term will be sent to the PUT by the input action
///     term!{fn_append_transcript(
///         (@server_hello_transcript),
///         (
///             // We can query our precomputation
///             (!"decrypted_extensions", 0)[
///                 Some(TlsQueryMatcher::Handshake(Some(HandshakeType::EncryptedExtensions)))
///             ] / Message
///         )
///     )}
/// };
/// ```
///
/// The following syntaxes are accepted :
/// ```ignore
/// # use puffin::input_action;
/// # use puffin::term;
/// # use puffin::trace::Precomputation;
/// # use puffin::trace::InputAction;
///
/// input_action!{term!{fn_msg()}};
/// input_action!{term!{fn_precomputation()} => term!{fn_msg()}};
/// input_action!{"this_is_a_label" = term!{fn_precomputation()} => term!{fn_msg()}};
/// input_action!{
///     "this_is_a_label" = term!{fn_precomputation_1()} =>
///         term!{fn_precomputation_2()} =>
///             term!{fn_msg()}
/// };
/// // the latter is equivalent to
/// input_action!{
///     "this_is_a_label" = term!{fn_precomputation_1()}, term!{fn_precomputation_2()} =>
///         term!{fn_msg()}
/// };
/// ```
///
/// All the previous examples respectively produce
/// ```ignore
/// # use puffin::trace::Precomputation;
/// # use puffin::trace::InputAction;
/// # use puffin::term;
/// # use crate::algebra::test_signature::fn_msg;
///
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![],
/// };
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![Precomputation{label: "".into(), recipe: term!{fn_precomputation()}}],
/// };
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![Precomputation{label: "this_is_a_label".into(), recipe:
/// term!{fn_precomputation()}}], };
/// InputAction {
///     recipe: term!{fn_msg()},
///     precomputations: vec![
///         Precomputation{label: "this_is_a_label".into(), recipe: term!{fn_precomputation_1()}},
///         Precomputation{label: "".into(), recipe: term!{fn_precomputation_2()}}
///     ],
/// };
/// ```
#[macro_export]
macro_rules! input_action {
    (@internal [$($label:expr, $precomp:expr);+] $recipe:expr) => {
        InputAction {
            recipe: $recipe,
            precomputations: vec![$(Precomputation{label: $label, recipe: $precomp}),*],
        }
    };

    (@internal [$($precomps:tt)+] $other_name:literal = $other_precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; Some($other_name.into()), $other_precomp] $($tail)+ }
    };

    (@internal [$($precomps:tt)+] $other_name:literal = $other_precomp:expr, $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; Some($other_name.into()), $other_precomp] $($tail)+ }
    };

    (@internal [$($precomps:tt)+] $other_precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; None, $other_precomp] $($tail)+ }
    };

    (@internal [$($precomps:tt)+] $other_precomp:expr, $($tail:tt)+) => {
        input_action!{@internal [$($precomps)+; None, $other_precomp] $($tail)+ }
    };

    ($precomp_name:literal = $precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [Some($precomp_name.into()), $precomp] $($tail)+ }
    };

    ($precomp_name:literal = $precomp:expr , $($tail:tt)+) => {
        input_action!{@internal [Some($precomp_name.into()), $precomp] $($tail)+ }
    };

    ($precomp:expr => $($tail:tt)+) => {
        input_action!{@internal [None, $precomp] $($tail)+ }
    };

    ($precomp:expr, $($tail:tt)+) => {
        input_action!{@internal [None, $precomp] $($tail)+ }
    };

    ($recipe:expr) => {
        InputAction {
            recipe: $recipe,
            precomputations: vec![],
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::algebra::test_signature::{
        fn_encrypt12, fn_finished, fn_new_random, fn_seq_0, fn_seq_1,
    };
    use crate::term;
    use crate::trace::{InputAction, Precomputation};

    #[test]
    fn test_input_action_macro() {
        let action0 = input_action! {term!{fn_seq_0()}};
        assert_eq!(action0.precomputations.len(), 0);

        let action1 = input_action! {
            term!{fn_new_random()} =>
                "a" = term!{fn_new_random()} =>
                    term!{
                        fn_encrypt12(fn_finished,fn_seq_0)
                    }
        };
        assert_eq!(action1.precomputations.len(), 2);
        assert_eq!(action1.precomputations[0].label, None);
        assert_eq!(action1.precomputations[1].label, Some("a".into()));

        let action2 = input_action! {
            "a" = term!{fn_new_random()}, "b" = term!{fn_finished()} =>
                term!{
                    fn_encrypt12(fn_finished,fn_seq_0)
                }
        };
        assert_eq!(action2.precomputations.len(), 2);
        assert_eq!(action2.precomputations[0].label, Some("a".into()));
        assert_eq!(action2.precomputations[1].label, Some("b".into()));

        let action3 = input_action! {
            "a" = term!{fn_new_random()} => term!{fn_finished()} =>
                term!{
                    fn_encrypt12(fn_finished,fn_seq_0)
                }
        };
        assert_eq!(action3.precomputations.len(), 2);
        assert_eq!(action3.precomputations[0].label, Some("a".into()));
        assert_eq!(action3.precomputations[1].label, None);

        let action4 = input_action! {
            term!{fn_finished()}, "a" = term!{fn_new_random()} =>
                term!{
                    fn_encrypt12(fn_finished,fn_seq_0)
                }
        };
        assert_eq!(action4.precomputations.len(), 2);
        assert_eq!(action4.precomputations[0].label, None);
        assert_eq!(action4.precomputations[1].label, Some("a".into()));

        let action5 = input_action! {
            term!{fn_finished()}, "a" = term!{fn_new_random()} =>
                "b" = term!{fn_seq_0()} =>
                    term!{fn_seq_1()} =>
                        "c" = term!{fn_seq_0()} =>
                            term!{fn_seq_0()}, "d" = term!{fn_seq_0()}, "e" = term!{fn_seq_0()} =>
                                term!{
                                    fn_encrypt12(fn_finished,fn_seq_0)
                                }
        };
        assert_eq!(action5.precomputations.len(), 8);
        assert_eq!(action5.precomputations[0].label, None);
        assert_eq!(action5.precomputations[1].label, Some("a".into()));
        assert_eq!(action5.precomputations[2].label, Some("b".into()));
        assert_eq!(action5.precomputations[3].label, None);
        assert_eq!(action5.precomputations[4].label, Some("c".into()));
        assert_eq!(action5.precomputations[5].label, None);
        assert_eq!(action5.precomputations[6].label, Some("d".into()));
        assert_eq!(action5.precomputations[7].label, Some("e".into()));
    }
}
