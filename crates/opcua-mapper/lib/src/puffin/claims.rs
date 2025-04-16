/// OPC UA claims are for the security properties AgrS and AgrC.
///
/// /!\ not implemented yet /!\
use std::fmt::Debug;

use crate::puffin::types::{AgentType, OpcuaProtocolTypes, OpcuaVersion};

use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::Claim;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

#[derive(Debug, Clone)]
pub struct OpcuaClaim {
    pub agent_name: AgentName,
    pub kind: AgentType,
    pub version: OpcuaVersion,
    //pub data: ClaimData,
}

impl Claim for OpcuaClaim {
    type PT = OpcuaProtocolTypes;

    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape<OpcuaProtocolTypes> {
        //type Type = TypeShape<OpcuaProtocolTypes>;
        panic!("Not implemented yet for OPC UA");
    }

    fn inner(&self) -> Box<dyn EvaluatedTerm<OpcuaProtocolTypes>> {
        panic!("Not implemented yet for OPC UA");
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, OpcuaClaim);

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
