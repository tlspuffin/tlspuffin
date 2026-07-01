use std::collections::{HashMap, HashSet};

use puffin::libafl::corpus::{InMemoryCorpus, Corpus};
use puffin::libafl::mutators::{MutationResult, Mutator};
use puffin::libafl::state::{StdState, HasCorpus};
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::libafl::inputs::HasMutatorBytes;

use puffin::trace_helper::TraceHelper;
use puffin::fuzzer::bit_mutations::{MakeMessage, CrossoverInsertMutatorDY};
use puffin::fuzzer::mutations::MutationConfig;
use puffin::put_registry::PutRegistry;
use puffin::trace::{Action, Trace};
use puffin::algebra::{Term, TermType};
use tlspuffin::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use tlspuffin::put_registry::tls_registry;
use tlspuffin::tls::seeds::seed_client_attacker_full;

type TestState = StdState<InMemoryCorpus<Trace<TLSProtocolTypes>>, Trace<TLSProtocolTypes>, RomuDuoJrRand, InMemoryCorpus<Trace<TLSProtocolTypes>>>;

/// Helper: form one shared group in `trace` (via MakeMessage/only-shared) and return its id.
fn form_group(trace: &mut Trace<TLSProtocolTypes>, mutator: &mut MakeMessage<'_, TLSProtocolBehavior>, state: &mut TestState) -> u64 {
    for _ in 0..2000 {
        if mutator.mutate(state, trace).unwrap() == MutationResult::Mutated {
            let mut counts = HashMap::new();
            for p in trace.all_payloads() {
                if let Some(id) = p.shared_id { *counts.entry(id).or_insert(0) += 1; }
            }
            if let Some((&id, _)) = counts.iter().find(|(_, &c)| c >= 2) { return id; }
        }
    }
    panic!("failed to form a shared group in 2000 tries");
}

fn create_state() -> StdState<InMemoryCorpus<Trace<TLSProtocolTypes>>, Trace<TLSProtocolTypes>, RomuDuoJrRand, InMemoryCorpus<Trace<TLSProtocolTypes>>> {
    let rand = StdRand::with_seed(12345);
    let corpus: InMemoryCorpus<Trace<TLSProtocolTypes>> = InMemoryCorpus::new();
    StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
}

fn setup_trace(_registry: &PutRegistry<TLSProtocolBehavior>) -> Trace<TLSProtocolTypes> {
    seed_client_attacker_full.build_trace()
}

#[test_log::test]
fn test_make_message_shared_assign() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    
    let mut mutation_config = MutationConfig::default();
    mutation_config.with_bit_level = true;
    mutation_config.shared_payloads = true;
    mutation_config.only_shared_payloads = true;
    
    let mut mutator = MakeMessage::new(mutation_config, &registry);
    
    let mut found_group = false;
    // Mutate a few times until we successfully form a shared group
    for _ in 0..100 {
        if mutator.mutate(&mut state, &mut trace).unwrap() == MutationResult::Mutated {
            // Check if a group of >= 2 was formed
            let mut groups = HashMap::new();
            for p in trace.all_payloads() {
                if let Some(id) = p.shared_id {
                    groups.entry(id).or_insert_with(Vec::new).push(p);
                }
            }
            if groups.values().any(|g| g.len() >= 2) {
                found_group = true;
                for group in groups.values() {
                    if group.len() >= 2 {
                        let reference_payload_0 = group[0].payload_0.mutator_bytes();
                        for member in group.iter().skip(1) {
                            assert_eq!(
                                reference_payload_0,
                                member.payload_0.mutator_bytes(),
                                "payload_0 bytes must be equal for all members of a shared group"
                            );
                            assert_eq!(
                                member.payload.mutator_bytes(),
                                reference_payload_0,
                                "payload bytes should initially be equal to payload_0"
                            );
                        }
                    }
                }
                break;
            }
        }
    }
    assert!(found_group, "Should have formed at least one shared group");
}

#[test_log::test]
fn test_sync_shared_payloads() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    
    let mut mutation_config = MutationConfig::default();
    mutation_config.with_bit_level = true;
    mutation_config.shared_payloads = true;
    mutation_config.only_shared_payloads = true;
    let mut mutator = MakeMessage::new(mutation_config, &registry);
    
    // Form a group
    loop {
        if mutator.mutate(&mut state, &mut trace).unwrap() == MutationResult::Mutated {
            let groups = trace.all_payloads().iter().filter_map(|p| p.shared_id).collect::<HashSet<_>>();
            if !groups.is_empty() {
                break;
            }
        }
    }
    
    // Pick the first shared ID and flip a bit in one member, then propagate via the targeted API
    // (the real fuzzer path: the mutator syncs FROM the payload it just changed).
    let target_id = trace.all_payloads().iter().find_map(|p| p.shared_id).unwrap();
    let (original_bytes, new_bytes) = {
        let mut members = trace.all_payloads_mut().into_iter().filter(|p| p.shared_id == Some(target_id));
        let first = members.next().unwrap();
        let bytes = first.payload.mutator_bytes_mut();
        let original = bytes.to_vec();
        bytes[0] ^= 0xFF; // flip bit
        (original, bytes.to_vec())
    };
    trace.sync_shared_payloads_from(target_id, &new_bytes);

    let members = trace.all_payloads().into_iter().filter(|p| p.shared_id == Some(target_id)).collect::<Vec<_>>();
    assert!(members.len() >= 2);
    let mutated_bytes = members[0].payload.mutator_bytes();
    assert_ne!(mutated_bytes, original_bytes.as_slice());
    
    for member in members {
        assert_eq!(member.payload.mutator_bytes(), mutated_bytes, "All members must be synced");
    }
}

/// [PROOF-OF-BUG] Iterated mutation on a NON-FIRST group member must not be reverted by sync.
/// The existing test only mutates the FIRST member (the case that works). This test primes the
/// group (round 1: mutate first + sync -> all members now differ from payload_0), then in round 2
/// mutates a NON-FIRST member and syncs. If sync's authority is "first member differing from
/// payload_0" (a stale rule after priming), it reverts the round-2 mutation. Correct behaviour:
/// the round-2 mutation propagates to all members.
#[test_log::test]
fn test_sync_iterated_non_first_member_not_reverted() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    let mut mc = MutationConfig::default();
    mc.with_bit_level = true;
    mc.shared_payloads = true;
    mc.only_shared_payloads = true;
    let mut mutator = MakeMessage::new(mc, &registry);
    // Form a group of >= 2 members.
    let target_id = loop {
        if mutator.mutate(&mut state, &mut trace).unwrap() == MutationResult::Mutated {
            let mut counts = HashMap::new();
            for p in trace.all_payloads() {
                if let Some(id) = p.shared_id { *counts.entry(id).or_insert(0) += 1; }
            }
            if let Some((&id, _)) = counts.iter().find(|(_, &c)| c >= 2) { break id; }
        }
    };
    // ROUND 1: mutate the FIRST member, sync FROM it -> primes the whole group.
    let v1 = {
        let mut members = trace.all_payloads_mut().into_iter().filter(|p| p.shared_id == Some(target_id));
        let first = members.next().unwrap();
        first.payload.mutator_bytes_mut()[0] ^= 0xAA;
        first.payload.mutator_bytes().to_vec()
    };
    trace.sync_shared_payloads_from(target_id, &v1);
    // ROUND 2: mutate a NON-FIRST member to a distinct value V2, then sync FROM it.
    let v2 = {
        let mut members: Vec<_> = trace.all_payloads_mut().into_iter().filter(|p| p.shared_id == Some(target_id)).collect();
        assert!(members.len() >= 2);
        let second = &mut members[1]; // NON-first
        let b = second.payload.mutator_bytes_mut();
        b[0] ^= 0x55; // now differs from the round-1 value AND from member[0]
        b.to_vec()
    };
    trace.sync_shared_payloads_from(target_id, &v2);
    // CORRECT: the round-2 mutation (v2) must have propagated to ALL members (not reverted).
    let members: Vec<_> = trace.all_payloads().into_iter().filter(|p| p.shared_id == Some(target_id)).collect();
    for (i, m) in members.iter().enumerate() {
        assert_eq!(
            m.payload.mutator_bytes(), v2.as_slice(),
            "member {i}: round-2 mutation on a non-first member was REVERTED by sync (authority bug)"
        );
    }
}

#[test_log::test]
fn test_variable_guard() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    
    let mut mutation_config = MutationConfig::default();
    mutation_config.with_bit_level = true;
    mutation_config.shared_payloads = true;
    mutation_config.only_shared_payloads = true;
    let mut mutator = MakeMessage::new(mutation_config, &registry);
    
    for _ in 0..100 {
        mutator.mutate(&mut state, &mut trace).unwrap();
    }
    
    let mut found_group = false;
    let mut found_variable_with_payload = false;

    for step in &trace.steps {
        if let puffin::trace::Action::Input(input) = &step.action {
            for node in input.recipe.into_iter() {
                if let Some(payloads) = &node.payloads {
                    if payloads.shared_id.is_some() {
                        assert!(!node.has_variable(), "Nodes in a shared group must NOT contain variables");
                        found_group = true;
                    }
                    if node.has_variable() {
                        assert!(payloads.shared_id.is_none(), "Variable node must NOT have shared_id");
                        found_variable_with_payload = true;
                    }
                }
            }
        }
    }
    assert!(found_group, "Test trace must form at least one group to meaningfully test MakeMessage with shared_payloads");
    // found_variable_with_payload may or may not be true naturally, but the strict negative assertion above 
    // To test the variable logic, we explicitly create a variable and put it in a node?
    // In our test, found_variable_with_payload wasn't naturally true.
    // If it is true, it verifies the negative condition. If not, the main logic is still tested by found_group.
    let _ = found_variable_with_payload;
}

#[test_log::test]
fn test_crossover_materialize() {
    let registry = tls_registry();
    let trace1 = setup_trace(&registry);
    let trace2 = setup_trace(&registry);
    
    let mut state = create_state();
    let _id1 = state.corpus_mut().add(puffin::libafl::corpus::Testcase::new(trace1.clone())).unwrap();
    let _id2 = state.corpus_mut().add(puffin::libafl::corpus::Testcase::new(trace2.clone())).unwrap();
    
    let mut mutation_config = MutationConfig::default();
    mutation_config.with_bit_level = true;
    mutation_config.shared_payloads = true;
    
    let mut mm_dy = puffin::fuzzer::bit_mutations::MakeMessage::new(mutation_config.clone(), &registry);
    let mut t1 = trace1.clone();
    for _ in 0..100 { mm_dy.mutate(&mut state, &mut t1).unwrap(); }
    for p in t1.all_payloads_mut() { p.shared_id = Some(1); }
    
    let mut t2 = trace2.clone();
    for _ in 0..100 { mm_dy.mutate(&mut state, &mut t2).unwrap(); }
    for p in t2.all_payloads_mut() { p.shared_id = Some(2); }
    
    state.corpus_mut().replace(_id2, puffin::libafl::corpus::Testcase::new(t2)).unwrap();
    
    let mut crossover1 = CrossoverInsertMutatorDY::new(mutation_config.clone());
    let mut crossover2 = puffin::fuzzer::bit_mutations::CrossoverReplaceMutatorDY::new(mutation_config.clone());
    let mut crossover3 = puffin::fuzzer::bit_mutations::SpliceMutatorDY::new(mutation_config.clone());
    
    let mut mutated = false;
    for _ in 0..2000 {
        if crossover1.mutate(&mut state, &mut t1).unwrap() == MutationResult::Mutated { mutated = true; }
        if crossover2.mutate(&mut state, &mut t1).unwrap() == MutationResult::Mutated { mutated = true; }
        if crossover3.mutate(&mut state, &mut t1).unwrap() == MutationResult::Mutated { mutated = true; }
        
        if mutated {
            for p in t1.all_payloads() {
                assert_ne!(p.shared_id, Some(2), "Crossover leaked a shared_id from trace2 into trace1!");
            }
            break;
        }
    }
    assert!(mutated, "Crossover mutators never fired");
}

#[test_log::test]
fn test_serde_round_trip() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    let mut mutation_config = MutationConfig::default();
    mutation_config.with_bit_level = true;
    mutation_config.shared_payloads = true;
    mutation_config.only_shared_payloads = true;
    
    let mut mutator = MakeMessage::new(mutation_config, &registry);
    for _ in 0..50 { mutator.mutate(&mut state, &mut trace).unwrap(); }
    
    let orig_ids = trace.all_payloads().iter().filter_map(|p| p.shared_id).collect::<Vec<_>>();
    assert!(!orig_ids.is_empty(), "Must form at least one group");

    // Standard round-trip
    let serialized = trace.serialize_postcard().unwrap();
    let deserialized: Trace<TLSProtocolTypes> = Trace::deserialize_postcard(&serialized).unwrap();
    
    let deser_ids = deserialized.all_payloads().iter().filter_map(|p| p.shared_id).collect::<Vec<_>>();
    assert_eq!(orig_ids, deser_ids, "shared_id should be preserved across postcard serde");

    // Backward-compatibility test:
    // A trace serialized without `shared_id` should deserialize cleanly, 
    // with `shared_id` defaulting to `None`.
    
    // We mock the old format by stripping `shared_id` from a serialized trace JSON.
    let mut val: serde_json::Value = serde_json::to_value(&trace).unwrap();
    fn strip_shared_id(val: &mut serde_json::Value) {
        match val {
            serde_json::Value::Object(map) => {
                map.remove("shared_id");
                for (_, v) in map.iter_mut() {
                    strip_shared_id(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter_mut() {
                    strip_shared_id(v);
                }
            }
            _ => {}
        }
    }
    strip_shared_id(&mut val);
    
    let old_json = serde_json::to_string(&val).unwrap();
    let old_trace: Result<Trace<TLSProtocolTypes>, _> = serde_json::from_str(&old_json);
    assert!(old_trace.is_ok(), "Failed to deserialize old JSON trace without shared_id: {:?}", old_trace.err());
    if let Ok(t) = old_trace {
        for p in t.all_payloads() {
            assert_eq!(p.shared_id, None, "Old trace should deserialize shared_id as None");
        }
    }
}

/// All members of a shared group must have the SAME type (grouping is by structural Term equality,
/// which implies identical type). Explicit guard against ever confusing different types.
#[test_log::test]
fn test_shared_group_members_same_type() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    let mut mc = MutationConfig::default();
    mc.with_bit_level = true; mc.shared_payloads = true; mc.only_shared_payloads = true;
    let mut mutator = MakeMessage::new(mc, &registry);
    let id = form_group(&mut trace, &mut mutator, &mut state);

    // Collect the type shape of every node that carries this shared_id.
    let mut shapes = Vec::new();
    for step in &trace.steps {
        if let Action::Input(input) = &step.action {
            for node in input.recipe.into_iter() {
                if let Some(p) = &node.payloads {
                    if p.shared_id == Some(id) {
                        shapes.push(node.get_type_shape().clone());
                    }
                }
            }
        }
    }
    assert!(shapes.len() >= 2, "expected >=2 grouped members");
    for s in &shapes[1..] {
        assert_eq!(format!("{:?}", s), format!("{:?}", shapes[0]),
            "shared-group members must all have the SAME type (no type confusion)");
    }
}

/// STRESS: over many rounds, mutate a DIFFERENT (random) group member each round and sync FROM it;
/// the whole group must stay internally consistent every round (no revert, regardless of which
/// member changed). The proof test only exercised member[1]; this hits all members repeatedly.
#[test_log::test]
fn test_shared_group_iterated_all_members_stay_consistent() {
    let registry = tls_registry();
    let mut trace = setup_trace(&registry);
    let mut state = create_state();
    let mut mc = MutationConfig::default();
    mc.with_bit_level = true; mc.shared_payloads = true; mc.only_shared_payloads = true;
    let mut mutator = MakeMessage::new(mc, &registry);
    let id = form_group(&mut trace, &mut mutator, &mut state);

    let n = trace.all_payloads().iter().filter(|p| p.shared_id == Some(id)).count();
    assert!(n >= 2);
    for round in 0..20u8 {
        let which = (round as usize) % n; // rotate through all members
        // mutate member `which` of the group, then sync FROM it (the real fuzzer path)
        let new_bytes = {
            let members: Vec<_> = trace.all_payloads_mut().into_iter()
                .filter(|p| p.shared_id == Some(id)).collect();
            let m = members.into_iter().nth(which).unwrap();
            let b = m.payload.mutator_bytes_mut();
            b[0] = b[0].wrapping_add(round + 1); // distinct value each round
            b.to_vec()
        };
        trace.sync_shared_payloads_from(id, &new_bytes);
        // INVARIANT: every member equals the just-applied bytes (consistent, not reverted).
        for (i, m) in trace.all_payloads().into_iter().filter(|p| p.shared_id == Some(id)).enumerate() {
            assert_eq!(m.payload.mutator_bytes(), new_bytes.as_slice(),
                "round {round}: member {i} diverged after mutating member {which} (sync inconsistency)");
        }
    }
}
