use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

/// Selects a piece of SSH knowledge by its message IDENTITY rather than by a
/// positional counter.
///
/// A DY query `(agent, n)[matcher]/Type` binds the `n`-th knowledge of `Type`
/// (after filtering by `matcher`). With no matcher, `n` is a raw position into the
/// agent's output — fragile: a mutation that changes how many messages precede
/// the one you want silently rebinds the query (this is why the relay seeds carry
/// comments like `// server NEWKEYS` next to `(server, 3)/RawSshMessage`). Tagging
/// each extracted message with this matcher lets a seed instead say
/// `(agent, 0)[Some(MsgType(21))]/RawSshMessage` — "the NEWKEYS", wherever it lands.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum SshQueryMatcher {
    /// The version-exchange banner line (`RawSshMessage::Banner`).
    Banner,
    /// A cleartext BPP packet, keyed by its SSH message number (RFC 4250 §4.1.2):
    /// e.g. 20 = KEXINIT, 21 = NEWKEYS, 30 = KEX_ECDH_INIT, 31 = KEX_ECDH_REPLY.
    MsgType(u8),
    /// An opaque post-NewKeys (encrypted) on-wire chunk (`RawSshMessage::OnWire`).
    /// Cannot be distinguished further without decryption.
    OnWire,
}

impl Matcher for SshQueryMatcher {
    fn matches(&self, matcher: &Self) -> bool {
        self == matcher
    }

    /// Uniform across every variant, ON PURPOSE. puffin sorts a query's candidate
    /// knowledges by specificity — a *stable* sort — before taking the counter-th.
    /// A constant value therefore preserves insertion order for the many existing
    /// position-based `[None]` queries: tagging knowledge with a matcher must not
    /// silently renumber them. (`Option<Matcher>` already gives `None` specificity
    /// 0 and `Some(_)` specificity `1 + inner`, so within one type all tagged
    /// knowledge shares specificity `2` and keeps its order.)
    fn specificity(&self) -> u32 {
        1
    }
}
