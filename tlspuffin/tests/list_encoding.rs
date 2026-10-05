//! Checks every registered TLS list type against the RFC vector declaration it implements:
//!
//! 1. the list carries no framing -- `encode(list) == encode(e1) ++ .. ++ encode(en)`, the
//!    `VecCodecWoSize` codec;
//! 2. the wrapper symbol taking it (`fn_ciphersuites`, ...) prefixes that with a length of the
//!    width its declaration calls for.

use std::collections::HashMap;

use puffin::algebra::atoms::Function;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::algebra::{DYTerm, Term, TermType};
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::libafl_bolts::rands::StdRand;
use puffin::trace::{Spawner, TraceContext};
use tlspuffin::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use tlspuffin::put_registry::tls_registry;
use tlspuffin::tls::TLS_SIGNATURE;

/// What the RFC says the wrapper writes in front of the element bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    /// A `<..>` vector with a length prefix of this many bytes.
    Length(usize),
    /// Same, but omitted entirely when empty: the field is optional in the enclosing message.
    LengthOrEmpty(usize),
    /// Adds more than a length (an extension type, ...); only checked for containing the body.
    Other,
    /// Reads its argument instead of embedding it, so no byte relation holds. Nothing to check.
    Transform,
}

use Framing::{Length, LengthOrEmpty, Other, Transform};

/// The wire framing each list wrapper must produce, from the vector declaration of its RFC.
///
/// `<lo..hi>` bounds decide the prefix width: `2^8-1` needs one byte, `2^16-1` two, `2^24-1`
/// three. The comment on each line is the declaration the width comes from.
const EXPECTED: &[(&str, Framing)] = &[
    ("fn_ciphersuites", Length(2)), // 8446 4.1.2  cipher_suites<2..2^16-2>
    ("fn_compressions", Length(1)), // 8446 4.1.2  legacy_compression_methods<1..2^8-1>
    ("fn_clientextensions", LengthOrEmpty(2)), /* 8446 4.1.2  extensions<8..2^16-1>, absent in
                                     * TLS 1.2 */
    ("fn_serverextensions", LengthOrEmpty(2)), // 8446 4.1.3  extensions<6..2^16-1>
    ("fn_helloretryextensions", LengthOrEmpty(2)), // 8446 4.1.4  extensions<6..2^16-1>
    ("fn_encryptedextensions", Length(2)),     // 8446 4.3.1  extensions<0..2^16-1>
    ("fn_certreqextensions", Length(2)),       // 8446 4.3.2  extensions<2..2^16-1>
    ("fn_certificateentries", Length(3)),      // 8446 4.4.2  certificate_list<0..2^24-1>
    ("fn_certificateextensions", Length(2)),   // 8446 4.4.2  extensions<0..2^16-1>
    ("fn_newsessionticketextensions", Length(2)), // 8446 4.6.1  extensions<0..2^16-2>
    ("fn_protocolversions", Length(1)),        // 8446 4.2.1  versions<2..254>
    ("fn_supportedsignatureschemes", Length(2)), /* 8446 4.2.3
                                                * supported_signature_algorithms<2..2^16-2> */
    ("fn_namedgroups", Length(2)), // 8446 4.2.7  named_group_list<2..2^16-1>
    ("fn_keyshareentries", Length(2)), // 8446 4.2.8  client_shares<0..2^16-1>
    ("fn_pskkeyexchangemodes", Length(1)), // 8446 4.2.9  ke_modes<1..255>
    ("fn_presharedkeyidentities", Length(2)), // 8446 4.2.11 identities<7..2^16-1>
    ("fn_certificatepayload", Length(3)), // 5246 7.4.2  certificate_list<0..2^24-1>
    ("fn_certificate", Length(3)), // 5246 7.4.2  opaque ASN1Cert<1..2^24-1>
    ("fn_clientcertificatetypes", Length(1)), // 5246 7.4.4  certificate_types<1..2^8-1>
    ("fn_ecpointformatlist", Length(1)), // 8422 5.1.2  ec_point_format_list<1..2^8-1>
    ("fn_servernamerequest", Length(2)), // 6066 3      server_name_list<1..2^16-1>
    ("fn_payloadu8", Length(1)),   // opaque x<0..2^8-1>, width stated by the name
    ("fn_payloadu16", Length(2)),  // opaque x<0..2^16-1>
    ("fn_payloadu24", Length(3)),  // opaque x<0..2^24-1>
    ("fn_vecu16ofpayloadu8", Length(2)), // 8446 4.2.4  certificate_authorities
    ("fn_vecu16ofpayloadu16", Length(2)), // 7301 3.1    protocol_name_list
    ("fn_payload", Length(0)),     // externally length'd
    ("fn_messageflight", Length(0)), // a flight is concatenated records, not a vector
    ("fn_opaquemessageflight", Length(0)),
    ("fn_clientextension_transportparameters", Other), // extension type + own u16 length
    ("fn_clientextension_transportparametersdraft", Other),
    ("fn_serverextension_transportparameters", Other),
    ("fn_serverextension_transportparametersdraft", Other),
    ("fn_session_ticket_offer_extension", Other),
    ("fn_psk", Other),                           // wraps the bytes in an `Option`
    ("fn_decode_client_ecdh_pubkey", Transform), // parses an ECDH public key out of them
    ("fn_decode_server_ecdh_pubkey", Transform),
];

/// `..::handshake::fn_ciphersuites` -> `fn_ciphersuites`.
fn short_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

fn context() -> TraceContext<TLSProtocolBehavior> {
    TraceContext::new(Spawner::new(tls_registry()))
}

/// Closed terms that evaluate, indexed by the type they build. Elements of a TLS list are rarely
/// constants, so they are generated rather than picked out of the signature.
fn element_pool(
    ctx: &TraceContext<TLSProtocolBehavior>,
) -> HashMap<TypeShape<TLSProtocolTypes>, Vec<Term<TLSProtocolTypes>>> {
    let mut rand = StdRand::with_seed(0x715_10c1);
    let zoo = TermZoo::<TLSProtocolBehavior>::generate(ctx, &TLS_SIGNATURE, &mut rand, 4, Some(6));

    let mut pool: HashMap<_, Vec<_>> = HashMap::new();
    for term in zoo.terms() {
        // A `no_det` symbol re-randomises on every evaluation, so no byte expectation holds.
        if term.has_no_det() {
            continue;
        }
        let entry = pool.entry(term.get_type_shape().clone()).or_default();
        if entry.len() < 2 && !entry.contains(term) {
            entry.push(term.clone());
        }
    }
    pool
}

fn encode(
    term: &Term<TLSProtocolTypes>,
    ctx: &TraceContext<TLSProtocolBehavior>,
) -> Option<Vec<u8>> {
    term.evaluate_symbolic(ctx).ok()
}

/// The `width`-byte big-endian length a vector of `len` bytes must carry.
fn expected_prefix(width: usize, len: usize) -> Vec<u8> {
    let bytes = (len as u64).to_be_bytes();
    bytes[bytes.len() - width..].to_vec()
}

#[test_log::test]
fn test_list_types_are_encoded_as_the_rfc_specifies() {
    let ctx = context();
    let pool = element_pool(&ctx);
    let mut failures: Vec<String> = vec![];
    let mut checked_wrappers: Vec<&str> = vec![];
    let mut skipped: Vec<String> = vec![];
    let mut unbuildable: Vec<String> = vec![];

    for (list_shape, element_shape) in TLS_SIGNATURE.list_types.shapes() {
        let mut elements = pool.get(element_shape).cloned().unwrap_or_default();
        if elements.len() == 1 {
            // One distinct element is enough: a repeated one still exposes a stray separator.
            elements.push(elements[0].clone());
        }
        let empty = Term::from(DYTerm::List(list_shape.clone(), vec![]));

        // Normally the list built from `elements`; when no element exists, any other term of the
        // list type, so the wrapper's framing is checked even though property 1 cannot be.
        let body_term = if elements.is_empty() {
            unbuildable.push(format!(
                "{} (no symbol of the algebra builds a {})",
                list_shape.name, element_shape.name
            ));
            let Some(substitute) = pool.get(list_shape).and_then(|terms| terms.first()) else {
                skipped.push(format!("{}: no term of this type at all", list_shape.name));
                continue;
            };
            substitute.clone()
        } else {
            Term::from(DYTerm::List(list_shape.clone(), elements.clone()))
        };

        let Some(body) = encode(&body_term, &ctx) else {
            skipped.push(format!("{}: does not evaluate", list_shape.name));
            continue;
        };

        // (1) The list carries no framing of its own.
        if !elements.is_empty() {
            let concatenated: Vec<u8> = elements
                .iter()
                .filter_map(|element| encode(element, &ctx))
                .flatten()
                .collect();
            if body != concatenated {
                failures.push(format!(
                    "{}: a list does not encode as the concatenation of its elements\n     list: \
                     {body:02x?}\n     concat: {concatenated:02x?}",
                    list_shape.name
                ));
            }
        }
        if !encode(&empty, &ctx).is_some_and(|bytes| bytes.is_empty()) {
            failures.push(format!(
                "{}: an empty list does not encode to an empty bitstring",
                list_shape.name
            ));
        }

        // (2) Each wrapper taking this list adds the framing its RFC declares.
        for (fn_shape, dynamic_fn) in &TLS_SIGNATURE.functions {
            if fn_shape.argument_types.len() != 1 || fn_shape.argument_types[0] != *list_shape {
                continue;
            }
            let name = short_name(fn_shape.name);
            let Some((_, framing)) = EXPECTED.iter().find(|(known, _)| *known == name) else {
                failures.push(format!(
                    "{name} takes a {} but no expected framing is recorded for it: add it to \
                     EXPECTED with the RFC vector declaration it comes from",
                    list_shape.name
                ));
                continue;
            };
            checked_wrappers.push(name);

            let apply = |argument: &Term<TLSProtocolTypes>| {
                Term::from(DYTerm::Application(
                    Function::new(fn_shape.clone(), dynamic_fn.clone()),
                    vec![argument.clone()],
                ))
            };
            let Some(wrapped) = encode(&apply(&body_term), &ctx) else {
                failures.push(format!("{name}: does not evaluate over a non-empty vector"));
                continue;
            };

            match framing {
                Length(width) | LengthOrEmpty(width) => {
                    let want: Vec<u8> = expected_prefix(*width, body.len())
                        .into_iter()
                        .chain(body.iter().copied())
                        .collect();
                    if wrapped != want {
                        failures.push(format!(
                            "{name}: expected a {width}-byte length prefix\n     want: \
                             {want:02x?}\n     got:  {wrapped:02x?}"
                        ));
                    }
                }
                Other => {
                    if !wrapped.windows(body.len()).any(|window| window == body) {
                        failures.push(format!(
                            "{name}: the encoded vector does not appear in the encoding"
                        ));
                    }
                }
                Transform => {}
            }

            if let Some(wrapped_empty) = encode(&apply(&empty), &ctx) {
                match framing {
                    Length(width) => {
                        let want = expected_prefix(*width, 0);
                        if wrapped_empty != want {
                            failures.push(format!(
                                "{name}: an empty vector must still carry its {width}-byte zero \
                                 length\n     want: {want:02x?}\n     got:  {wrapped_empty:02x?}"
                            ));
                        }
                    }
                    LengthOrEmpty(_) => {
                        if !wrapped_empty.is_empty() {
                            failures.push(format!(
                                "{name}: an empty optional vector must encode to nothing, got \
                                 {wrapped_empty:02x?}"
                            ));
                        }
                    }
                    Other | Transform => {}
                }
            }
        }
    }

    for note in &skipped {
        log::warn!("[list encoding] skipped {note}");
    }
    // Such a list type can only ever be empty, so registering it buys the fuzzer nothing.
    for note in &unbuildable {
        log::warn!("[list encoding] no element can be built for {note}");
    }
    log::info!(
        "[list encoding] checked {} wrappers: {}",
        checked_wrappers.len(),
        checked_wrappers.join(", ")
    );

    assert!(
        failures.is_empty(),
        "{} list encoding(s) do not match the specification:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}
