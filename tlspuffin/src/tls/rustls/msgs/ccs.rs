use comparable::Comparable;
use constructor_macro::Constructor;
use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};

use crate::protocol::TLSProtocolTypes;
use crate::tls::{TLS_SIGNATURE_FNDEFS, TLS_SIGNATURE_TYPEDEFS};

#[derive(Debug, Clone, Extractable, Comparable, Constructor)]
#[extractable(TLSProtocolTypes)]
#[constructor(TLS_SIGNATURE, TLSProtocolTypes)]
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
