use comparable::Comparable;
use constructor_macro::Constructor;
use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};

use crate::protocol::TLSProtocolTypes;
use crate::tls::rustls::msgs::enums::{AlertDescription, AlertLevel};
use crate::tls::{TLS_SIGNATURE_FNDEFS, TLS_SIGNATURE_TYPEDEFS};

#[derive(Debug, Clone, Extractable, Comparable, Constructor)]
#[extractable(TLSProtocolTypes)]
#[constructor(TLS_SIGNATURE, TLSProtocolTypes)]
pub struct AlertMessagePayload {
    #[extractable_no_recursion]
    pub level: AlertLevel,
    #[extractable_no_recursion]
    pub description: AlertDescription,
}

impl Codec for AlertMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.level.encode(bytes);
        self.description.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;

        Some(Self { level, description })
    }
}
