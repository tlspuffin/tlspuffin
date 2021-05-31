use ring::hkdf;
use ring::hkdf::KeyType;

pub enum SecretKind {
    ResumptionPSKBinderKey,
    ClientEarlyTrafficSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ExporterMasterSecret,
    ResumptionMasterSecret,
    DerivedSecret,
}

impl SecretKind {
    fn to_bytes(&self) -> &'static [u8] {
        match self {
            SecretKind::ResumptionPSKBinderKey => b"res binder",
            SecretKind::ClientEarlyTrafficSecret => b"c e traffic",
            SecretKind::ClientHandshakeTrafficSecret => b"c hs traffic",
            SecretKind::ServerHandshakeTrafficSecret => b"s hs traffic",
            SecretKind::ClientApplicationTrafficSecret => b"c ap traffic",
            SecretKind::ServerApplicationTrafficSecret => b"s ap traffic",
            SecretKind::ExporterMasterSecret => b"exp master",
            SecretKind::ResumptionMasterSecret => b"res master",
            SecretKind::DerivedSecret => b"derived",
        }
    }
}

pub fn derive_secret<L, F, T>(
    secret: &hkdf::Prk,
    kind: SecretKind,
    algorithm: L,
    context: &Vec<u8>,
    into: F,
) -> T
    where
        L: KeyType,
        F: for<'b> FnOnce(hkdf::Okm<'b, L>) -> T,
{
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let label = kind.to_bytes();
    let output_len = u16::to_be_bytes(algorithm.len() as u16);
    let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
    let context_len = u8::to_be_bytes(context.len() as u8);

    let info = &[
        &output_len[..],
        &label_len[..],
        LABEL_PREFIX,
        label,
        &context_len[..],
        context,
    ];
    let okm = secret.expand(info, algorithm).unwrap();
    into(okm)
}