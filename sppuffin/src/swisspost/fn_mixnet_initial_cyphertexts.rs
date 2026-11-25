use comparable::Comparable;
use puffin::algebra::error::FnError;
use puffin::error::Error as PuffinError;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use serde::{Deserialize, Serialize};

use crate::swisspost::SwissProtocolTypes;

const ELECTION_EVENT_ID: &str = "00000000-0000-0000-0000-000000000001";
const BALLOT_BOX_ID: &str = "00000000-0000-0000-0000-000000000002";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Comparable)]
#[serde(rename_all = "camelCase")]
pub struct MixDecryptOnlineRequestPayload {
    election_event_id: String,
    ballot_box_id: String,
    node_id: i32,
    control_component_votes_hash_payloads: Vec<ControlComponentVotesHashPayload>,
    control_component_shuffle_payloads: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Comparable)]
#[serde(rename_all = "camelCase")]
struct ControlComponentVotesHashPayload {
    election_event_id: String,
    ballot_box_id: String,
    node_id: i32,
    encrypted_confirmed_votes_hash: String,
    signature: CryptoPrimitivesSignature,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Comparable)]
#[serde(rename_all = "camelCase")]
struct CryptoPrimitivesSignature {
    signature_contents: String,
}

impl MixDecryptOnlineRequestPayload {
    fn encode_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

impl puffin::codec::Codec for MixDecryptOnlineRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self.encode_json() {
            Ok(encoded) => bytes.extend_from_slice(&encoded),
            Err(error) => log::error!("Failed to encode mix-decrypt request: {error}"),
        }
    }

    fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        serde_json::from_slice(r.rest()).ok()
    }
}

impl Extractable<SwissProtocolTypes> for MixDecryptOnlineRequestPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SwissProtocolTypes>>,
        matcher: Option<<SwissProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), PuffinError> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        Ok(())
    }
}

pub fn fn_mix_decrypt_online_request() -> Result<MixDecryptOnlineRequestPayload, FnError> {
    let encrypted_confirmed_votes_hash = format!("{}=", "A".repeat(43));
    let signature = CryptoPrimitivesSignature {
        signature_contents: "AA==".to_string(),
    };
    let control_component_votes_hash_payloads = (1..=4)
        .map(|node_id| ControlComponentVotesHashPayload {
            election_event_id: ELECTION_EVENT_ID.to_string(),
            ballot_box_id: BALLOT_BOX_ID.to_string(),
            node_id,
            encrypted_confirmed_votes_hash: encrypted_confirmed_votes_hash.clone(),
            signature: signature.clone(),
        })
        .collect();

    Ok(MixDecryptOnlineRequestPayload {
        election_event_id: ELECTION_EVENT_ID.to_string(),
        ballot_box_id: BALLOT_BOX_ID.to_string(),
        node_id: 1,
        control_component_votes_hash_payloads,
        control_component_shuffle_payloads: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use puffin::codec::Codec;

    #[test]
    fn mix_decrypt_payload_codec_round_trips_expected_json_shape() {
        let payload = fn_mix_decrypt_online_request().unwrap();
        let encoded = payload.get_encoding();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(json["nodeId"], 1);
        assert_eq!(
            json["controlComponentVotesHashPayloads"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            json["controlComponentShufflePayloads"],
            serde_json::json!([])
        );
        assert_eq!(
            json["controlComponentVotesHashPayloads"][0]["signature"]["signatureContents"],
            "AA=="
        );

        let decoded = MixDecryptOnlineRequestPayload::read_bytes(&encoded).unwrap();
        assert_eq!(decoded.get_encoding(), encoded);
    }
}
