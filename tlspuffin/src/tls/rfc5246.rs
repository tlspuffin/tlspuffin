// CLAUDE
//! Oracle de conformité RFC 5246 (TLS 1.2) sur les octets réellement échangés.
//! Les messages ÉMIS par le PUT sont jugés ; les messages reçus servent de
//! contexte (l'attaquant est volontairement non conforme). Un message reçu hors
//! séquence n'est une violation du PUT que s'il n'y répond pas par une alerte fatale.

use puffin::codec::Codec;
use puffin::trace::{Direction, StepNumber, TraceContext};

use crate::protocol::{AgentType, OpaqueMessageFlight, TLSProtocolBehavior, TLSVersion};
use crate::tls::rustls::msgs::enums::{
    AlertLevel, CipherSuite, ContentType, ExtensionType, HandshakeType, ProtocolVersion,
};
use crate::tls::rustls::msgs::handshake::{ClientHelloPayload, HandshakePayload, ServerHelloPayload};
use crate::tls::rustls::msgs::message::{Message, MessagePayload, OpaqueMessage};

type Violation = &'static str;

const MAX_PLAINTEXT: usize = 1 << 14;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;

pub fn check(ctx: &TraceContext<TLSProtocolBehavior>) -> Option<Violation> {
    for agent in ctx.agents() {
        let cfg = &agent.descriptor().protocol_config;
        if cfg.tls_version != TLSVersion::V1_2 {
            continue;
        }

        let mut st = State::new(cfg.typ);
        for ev in ctx.wire_log().iter().filter(|e| e.agent == agent.name()) {
            let Some(flight) = OpaqueMessageFlight::read_bytes(&ev.bytes) else {
                continue;
            };
            match ev.direction {
                Direction::Inbound => {
                    for rec in flight.messages {
                        st.on_received(rec, &ev.step);
                    }
                }
                Direction::Outbound => {
                    // §7.2.2 : après réception d'une alerte fatale, la connexion est fermée.
                    // On tolère une réponse dans le même step (ex. alerte en retour).
                    if matches!(&st.peer_fatal_at, Some(s) if *s != ev.step) {
                        return Some("RFC5246 §7.2.2: data sent after receiving a fatal alert");
                    }
                    for rec in flight.messages {
                        if let Err(v) = st.on_sent(rec) {
                            return Some(v);
                        }
                    }
                }
            }
        }

        // §7.4 + §7.2.2 : un message hors séquence MUST provoquer une alerte fatale
        if st.peer_violation && !st.sent_fatal {
            return Some(
                "RFC5246 §7.4: out-of-order handshake message accepted without fatal alert",
            );
        }
    }
    None
}

/// Rang autorisé de chaque message handshake émis, par rôle (§7.3, figure 1).
/// Les rangs doivent être strictement croissants. `None` = interdit pour ce rôle.
fn rank(role: AgentType, t: HandshakeType) -> Option<u8> {
    use HandshakeType::*;
    match (role, t) {
        (AgentType::Server, ServerHello) => Some(1),
        (AgentType::Server, Certificate) => Some(2),
        (AgentType::Server, ServerKeyExchange) => Some(3),
        (AgentType::Server, CertificateRequest) => Some(4),
        (AgentType::Server, ServerHelloDone) => Some(5),
        (AgentType::Server, NewSessionTicket) => Some(6),
        (AgentType::Client, ClientHello) => Some(1),
        (AgentType::Client, Certificate) => Some(2),
        (AgentType::Client, ClientKeyExchange) => Some(3),
        (AgentType::Client, CertificateVerify) => Some(4),
        _ => None,
    }
}

struct State {
    role: AgentType,
    last_rank: u8,
    negotiated: Option<ProtocolVersion>,
    // ce que l'agent a émis
    sent_sh: bool,
    sent_shd: bool,
    sent_cert: bool,
    sent_cke: bool,
    sent_ccs: bool,
    sent_finished: bool,
    sent_fatal: bool,
    sent_cert_req: bool,
    // ce que l'agent a reçu
    recv_ch: Option<ClientHelloPayload>,
    recv_shd: bool,
    recv_cert_req: bool,
    recv_cert: bool,
    recv_cke: bool,
    recv_ccs: bool,
    recv_finished: bool,
    peer_fatal_at: Option<StepNumber>,
    /// le pair a envoyé un message handshake hors séquence
    peer_violation: bool,
}

impl State {
    fn new(role: AgentType) -> Self {
        Self {
            role,
            last_rank: 0,
            negotiated: None,
            sent_sh: false,
            sent_shd: false,
            sent_cert: false,
            sent_cke: false,
            sent_ccs: false,
            sent_finished: false,
            sent_fatal: false,
            sent_cert_req: false,
            recv_ch: None,
            recv_shd: false,
            recv_cert_req: false,
            recv_cert: false,
            recv_cke: false,
            recv_ccs: false,
            recv_finished: false,
            peer_fatal_at: None,
            peer_violation: false,
        }
    }

    // ---------- contexte : messages reçus ----------

    fn on_received(&mut self, rec: OpaqueMessage, step: &StepNumber) {
        match rec.typ {
            ContentType::ChangeCipherSpec => self.recv_ccs = true,
            // Après CCS tout est chiffré : on suppose que le 1er handshake est Finished.
            ContentType::Handshake if self.recv_ccs => self.recv_finished = true,
            ContentType::Handshake => {
                if let Ok(Message { payload: MessagePayload::Handshake(hs), .. }) =
                    Message::try_from(rec)
                {
                    match hs.payload {
                        HandshakePayload::ClientHello(ch) => self.recv_ch = Some(ch),
                        HandshakePayload::ServerHello(sh)
                            if sh.legacy_version == ProtocolVersion::TLSv1_2 =>
                        {
                            self.negotiated = Some(sh.legacy_version)
                        }
                        HandshakePayload::CertificateRequest(_) => self.recv_cert_req = true,
                        HandshakePayload::ServerHelloDone => self.recv_shd = true,
                        // §7.4.6 : seulement après une CertificateRequest, avant le CKE
                        HandshakePayload::Certificate(_) if self.role == AgentType::Server => {
                            if !self.sent_cert_req || !self.sent_shd || self.recv_cke {
                                self.peer_violation = true;
                            }
                            self.recv_cert = true;
                        }
                        // §7.4.7 : après ServerHelloDone, et après Certificate si demandé
                        HandshakePayload::ClientKeyExchange(_)
                            if self.role == AgentType::Server =>
                        {
                            if !self.sent_shd
                                || (self.sent_cert_req && !self.recv_cert)
                                || self.recv_cke
                            {
                                self.peer_violation = true;
                            }
                            self.recv_cke = true;
                        }
                        // §7.4.8 : MUST immediately follow the client key exchange message
                        HandshakePayload::CertificateVerify(_)
                            if self.role == AgentType::Server =>
                        {
                            if !self.recv_cke || !self.recv_cert {
                                self.peer_violation = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            ContentType::Alert if !self.recv_ccs => {
                if let Ok(Message { payload: MessagePayload::Alert(a), .. }) =
                    Message::try_from(rec)
                {
                    if a.level == AlertLevel::Fatal {
                        self.peer_fatal_at = Some(step.clone());
                    }
                }
            }
            _ => {}
        }
    }

    // ---------- jugement : messages émis ----------

    fn on_sent(&mut self, rec: OpaqueMessage) -> Result<(), Violation> {
        if self.sent_fatal {
            return Err("RFC5246 §7.2.2: record sent after own fatal alert");
        }

        let limit = if self.sent_ccs { MAX_CIPHERTEXT } else { MAX_PLAINTEXT };
        if rec.payload.0.len() > limit {
            return Err("RFC5246 §6.2: record length exceeds limit");
        }
        if let Some(v) = self.negotiated {
            if rec.version != v {
                return Err("RFC5246 §6.2.1: record version differs from negotiated version");
            }
        }

        match rec.typ {
            ContentType::ChangeCipherSpec => self.on_sent_ccs(),
            ContentType::Handshake => self.on_sent_handshake(rec),
            ContentType::ApplicationData => {
                if !(self.sent_finished && self.recv_finished) {
                    return Err("RFC5246 §7.4.9: application data before handshake completion");
                }
                Ok(())
            }
            ContentType::Alert => {
                if !self.sent_ccs {
                    if let Ok(Message { payload: MessagePayload::Alert(a), .. }) =
                        Message::try_from(rec)
                    {
                        self.sent_fatal = a.level == AlertLevel::Fatal;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn on_sent_ccs(&mut self) -> Result<(), Violation> {
        if self.sent_ccs {
            return Err("RFC5246 §7.1: ChangeCipherSpec sent twice");
        }
        let ok = match self.role {
            // complet : après le Finished client ; abrégé (pas de SHD) : juste après SH/NST
            AgentType::Server => self.sent_sh && (!self.sent_shd || self.recv_finished),
            // complet : après CKE ; abrégé : après le Finished serveur
            AgentType::Client => self.sent_cke || self.recv_finished,
        };
        if !ok {
            return Err("RFC5246 §7.3: ChangeCipherSpec sent too early");
        }
        self.sent_ccs = true;
        Ok(())
    }

    fn on_sent_handshake(&mut self, rec: OpaqueMessage) -> Result<(), Violation> {
        if self.sent_ccs {
            // Chiffré : le 1er record handshake après CCS est Finished.
            // Au-delà (renégociation, HelloRequest) : non vérifié.
            self.sent_finished = true;
            return Ok(());
        }

        let hs = match Message::try_from(rec) {
            Ok(Message { payload: MessagePayload::Handshake(hs), .. }) => hs,
            // Non parsable / plusieurs messages coalescés dans un record : on ignore
            // plutôt que de produire un faux positif.
            _ => return Ok(()),
        };

        if hs.typ == HandshakeType::HelloRequest && self.role == AgentType::Server {
            return Ok(());
        }
        let Some(r) = rank(self.role, hs.typ) else {
            return Err("RFC5246 §7.4: handshake message type not allowed for this role");
        };
        if self.last_rank == 0 && r != 1 {
            return Err("RFC5246 §7.3: first handshake message must be a Hello");
        }
        if r <= self.last_rank {
            return Err("RFC5246 §7.3: handshake message out of order or repeated");
        }
        self.last_rank = r;

        match hs.payload {
            HandshakePayload::ServerHello(sh) => {
                self.check_server_hello(&sh)?;
                self.negotiated = Some(sh.legacy_version);
                self.sent_sh = true;
            }
            HandshakePayload::ServerHelloDone => self.sent_shd = true,
            HandshakePayload::CertificateRequest(_) => self.sent_cert_req = true,
            HandshakePayload::Certificate(_) => self.sent_cert = true,
            HandshakePayload::ClientKeyExchange(_) => {
                if !self.recv_shd {
                    return Err("RFC5246 §7.4.7: ClientKeyExchange before ServerHelloDone");
                }
                if self.recv_cert_req && !self.sent_cert {
                    return Err("RFC5246 §7.4.6: Certificate missing after CertificateRequest");
                }
                self.sent_cke = true;
            }
            _ => {}
        }
        Ok(())
    }

    /// §7.4.1.3 / §7.4.1.4 : le ServerHello doit être cohérent avec le ClientHello reçu.
    fn check_server_hello(&self, sh: &ServerHelloPayload) -> Result<(), Violation> {
        let Some(ch) = &self.recv_ch else {
            return Err("RFC5246 §7.4.1.3: ServerHello without ClientHello");
        };
        if sh.legacy_version.get_u16() > ch.client_version.get_u16() {
            return Err("RFC5246 §7.4.1.3: server_version higher than client_version");
        }
        if !ch.cipher_suites.0.contains(&sh.cipher_suite) {
            return Err("RFC5246 §7.4.1.3: cipher_suite not offered by client");
        }
        if !ch.compression_methods.0.contains(&sh.compression_method) {
            return Err("RFC5246 §7.4.1.3: compression_method not offered by client");
        }

        let scsv = ch
            .cipher_suites
            .0
            .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        let mut seen: Vec<ExtensionType> = vec![];
        for ext in &sh.extensions.0 {
            let t = ext.get_type();
            if seen.contains(&t) {
                return Err("RFC5246 §7.4.1.4: duplicate extension in ServerHello");
            }
            seen.push(t);
            // RFC 5746 : renegotiation_info autorisé si le client a envoyé la SCSV
            let allowed_by_scsv = t == ExtensionType::RenegotiationInfo && scsv;
            if ch.find_extension(t).is_none() && !allowed_by_scsv {
                return Err("RFC5246 §7.4.1.4: ServerHello extension not offered by client");
            }
        }
        Ok(())
    }
}
