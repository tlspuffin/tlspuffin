/// OPC UA claims are for the security properties AgrS and AgrC.
///
/// /!\ not implemented yet /!\
use std::fmt::Debug;

use opcua::puffin::types::{OpcuaProtocolTypes};

use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::Claim;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source, StepNumber};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

// copied from sshpuffin (claim.rs)
#[derive(Debug, Clone)]
pub struct OpcuaClaimInner;
dummy_extract_knowledge_codec!(OpcuaProtocolTypes, Box<OpcuaClaimInner>);

#[derive(Debug, Clone)]
pub struct OpcuaClaim {
    agent_name: AgentName,
    inner: Box<OpcuaClaimInner>,
    step: Option<StepNumber>
}

impl Claim for OpcuaClaim {
    type PT = OpcuaProtocolTypes;

    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape<OpcuaProtocolTypes> {
        TypeShape::of::<OpcuaClaimInner>()
    }

    fn inner(&self) -> Box<dyn EvaluatedTerm<OpcuaProtocolTypes>> {
        Box::new(self.inner.clone())
    }

    fn set_step(&mut self, step: Option<StepNumber>) {
        self.step = step;
    }

    fn get_step(&self) -> Option<StepNumber> {
        self.step.clone()
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, OpcuaClaim);

// The DDYF Claim bounds in the puffin base require `Comparable` + `PartialEq`. OPC UA does not do
// differential claim comparison; use non-recursing dummy impls (see `opcua::dummy_comparable!`).
opcua::dummy_comparable!(OpcuaClaim, OpcuaClaimInner);
impl PartialEq for OpcuaClaim {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

// impl Extractable<OpcuaProtocolTypes> for OpcuaClaim {
//     fn extract_knowledge(
//         &self,
//         _knowledges: &mut Vec<puffin::trace::Knowledge<OpcuaProtocolTypes>>,
//         _matcher: Option<<OpcuaProtocolTypes as puffin::protocol::ProtocolTypes>::Matcher>,
//         _source: &puffin::trace::Source,
//     ) -> Result<(), puffin::error::Error> {
//         Ok(())
//     }
// }
