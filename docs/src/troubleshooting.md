## Fuzzer-respawner: Storing state in crashed fuzzer instance did not work, no point to spawn the next client! (Child exited with: 25856)

Add `panic = "abort"` to your Cargo.toml:

```toml
[features]

[profile.release]
panic = "abort"
lto = true
codegen-units = 1
opt-level = 3
debug = true

[profile.dev]
panic = "abort"
```

## An error occurred while fuzzing: Empty("No entries in corpus")

Either your corpus directory is empty or no testcase from `corpus` is interesting. You can try to add a TimeoutFeedback
and return `ExitKind::Timeout` from the harness to make the testcase `is_interresting`.


## Fuzzing is very slow

* Watch the size of your corpus. Is it exploding very fast? If yes, then maybe too many runs are "interesting".
  This means that a lot of inputs will be added to the corpus, which increases for example the serialization overhead.
  