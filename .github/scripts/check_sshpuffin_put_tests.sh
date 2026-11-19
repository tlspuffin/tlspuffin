#!/usr/bin/env bash
# The PUT tests of sshpuffin (tests/determinism.rs, tests/traces.rs) only compile when a PUT of
# their vendor is built: a missing vendor would silently drop them and still pass.
# Usage: check_sshpuffin_put_tests.sh <log of `just test sshpuffin`>
set -u
log=${1:?log of the sshpuffin tests}
for t in \
  libssh_put_is_deterministic \
  wolfssh_put_is_deterministic \
  two_party_seeds_reach_their_verdict \
  server_session_clients_reach_done \
  corpus_seeds_run_on_every_put \
  rekey_complete_is_answered_after_the_rekey \
  make_message_on_sealed_steps_keeps_the_rekey_answered \
  harnesses_decide_the_same \
  a_refused_service_ends_the_session \
  an_error_after_the_handshake_ends_the_session \
  an_error_after_the_client_handshake_ends_the_session \
  a_channel_closed_before_any_request_leaves_the_session_running \
  a_packet_behind_channel_data_is_handled_in_the_same_step \
  a_user_name_that_is_not_an_allowed_one_is_refused \
  a_disconnect_after_the_handshake_ends_the_session \
  the_session_id_claim_comes_at_the_peer_newkeys \
  a_differential_runs_both_executions_from_the_same_seed \
  display_execute_shows_the_stored_recipe_and_the_sent_bytes; do
  grep -q "^test $t \.\.\. ok" "$log" || {
    echo "::error::sshpuffin test $t did not run (PUT not built?)"
    exit 1
  }
done
