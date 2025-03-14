use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};

use crate::protocol::TLSProtocolTypes;

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct ChangeCipherSpecPayload;

impl Codec for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let _typ = u8::read(r)?;

        Some(Self {})
    }
}
