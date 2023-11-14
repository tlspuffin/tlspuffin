pub mod bio;
pub mod callbacks;
pub mod error;
#[cfg(not(feature = "wolfssl430"))]
pub mod pkey;
#[cfg(not(feature = "wolfssl430"))]
pub mod rsa;
pub mod ssl;
pub mod util;
pub mod version;
pub mod x509;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TLSVersion {
    V1_3,
    V1_2,
}
