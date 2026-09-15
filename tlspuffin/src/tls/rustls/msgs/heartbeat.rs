use comparable::Comparable;
use constructor_macro::Constructor;
use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};

use crate::protocol::TLSProtocolTypes;
use crate::tls::rustls::msgs::base::PayloadU16;
use crate::tls::rustls::msgs::enums::HeartbeatMessageType;
use crate::tls::{TLS_SIGNATURE_FNDEFS, TLS_SIGNATURE_TYPEDEFS};

#[derive(Debug, Clone, Extractable, Comparable, Constructor)]
#[extractable(TLSProtocolTypes)]
#[constructor(TLS_SIGNATURE, TLSProtocolTypes)]
pub struct HeartbeatPayload {
    #[extractable_ignore]
    pub typ: HeartbeatMessageType,
    pub payload: PayloadU16,
    /// Derived from the payload rather than exposed as a constructor parameter: `Option<u16>` is
    /// not a registrable type, and a length that disagrees with the payload is what bit-level
    /// mutations are for.
    #[constructor_default(Some(payload.0.len() as u16))]
    pub fake_length: Option<u16>,
}

impl Codec for HeartbeatPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        if let Some(fake_length) = self.fake_length {
            fake_length.encode(bytes);
            bytes.extend_from_slice(self.payload.0.as_slice());
        } else {
            self.payload.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<HeartbeatPayload> {
        let typ = HeartbeatMessageType::read(r)?;
        let payload = PayloadU16::read(r)?;

        Some(HeartbeatPayload {
            typ,
            payload,
            fake_length: None,
        })
    }
}
