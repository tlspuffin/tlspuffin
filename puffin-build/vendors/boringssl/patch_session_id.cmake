# patch_session_id.cmake — Relax BoringSSL's strict session ID validation for
# differential fuzzing.
#
# BoringSSL rejects TLS 1.2 connections where the server echoes back the
# synthetic legacy_session_id that BoringSSL sends in its TLS 1.3-compat
# ClientHello (SERVER_ECHOED_INVALID_SESSION_ID, handshake_client.cc:738).
# OpenSSL does not perform this check and proceeds normally.
#
# Root cause: BoringSSL always includes a non-empty synthetic session_id in
# ClientHello for middlebox compatibility. When the fuzzer (acting as server
# attacker) echoes this session_id back in ServerHello, BoringSSL interprets
# it as a session resumption attempt, but then rejects it because no matching
# session exists on the client side.
#
# Fix: Guard the resumption block with `ssl->session != nullptr` so that if
# there is no session to resume, BoringSSL falls through to the `else` branch
# (fresh handshake creation), exactly as OpenSSL behaves.
#
# This preserves real session resumption logic (all inner checks still apply
# when `ssl->session != nullptr`); only the spurious rejection of echoed
# synthetic session IDs is removed.

file(READ "${FILE}" content)
string(REPLACE
  "  if (!hs->session_id.empty() &&
      Span<const uint8_t>(server_hello.session_id) == hs->session_id) {"
  "  if (ssl->session != nullptr && ssl->s3->ech_status != ssl_ech_rejected &&
      !hs->session_id.empty() &&
      Span<const uint8_t>(server_hello.session_id) == hs->session_id) {"
  content "${content}")
file(WRITE "${FILE}" "${content}")

