use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};

use crate::protocol::TLSProtocolTypes;
use crate::tls::rustls::msgs::enums::{AlertDescription, AlertLevel};

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
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
