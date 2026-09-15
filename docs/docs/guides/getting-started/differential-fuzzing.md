---
title: 'Differential fuzzing with Puffin'
---

## Differential fuzzing

*Puffin* based fuzzers can do _differential fuzzing_ between two PUTs: each trace is executed on the two PUTs and if their executions are different (execution status, knowledge, claims) the trace is flagged as an objective.


## Requirements

 In order to do differential fuzzing, the protocol fuzzer should be configured to minimize the false positives, i.e. all randomized fields (nonces, random, secrets, hash, ciphertext, etc.) should be annotated to be ignored during the comparison step. If the protocol offers some customization (e.g. cipher selection), the protocol fuzzer must provide a set of common parameters for all the PUTs to minimize the difference. The fuzzer might also provide a set of terms to decipher the encrypted messages sent by the PUTs by leveraging the secrets extracted via the claims.

## Supported PUTs

### tlspuffin

Currently differential fuzzing works for `OpenSSL 3.4.0` and `wolfSSL 5.0.0` to `5.8.0`. Other PUTs/versions might exhibit false positives in seed traces.


## Starting a differential fuzzing campaign

To do _differential fuzzing_, we first need to build two PUTs. OpenSSL and wolfSSL are both ready for _differential fuzzing_:

```sh
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
```

Then we can build the fuzzer:

```sh
cargo build --release --bin=tlspuffin --features=cputs
```

And generate the seeds using the `--differential` flag to set the configuration of the PUTs to a common set of parameters:

```sh
./target/release/tlspuffin seed --differential
```

Now we can run the fuzzer:


```sh
./target/release/tlspuffin --cores 0-3 differential openssl340 wolfssl580
```


:::tip[Number of objectives]
_Differential fuzzing_ campaigns tend to generate a lot of objectives (hundred of thousands to millions for 24h campaigns) so make sure to have some space left on your drive (at least multiple GB).
:::


## Replaying objectives


To replay the objectives traces and view the differences, you can use the `differential-execute` command:

```sh
./target/release/tlspuffin differential-execute openssl340 wolfssl580 path/to/trace
```

To replay the objectives on only one PUT to have the details of the executions: 

```sh
./target/release/tlspuffin --put openssl340 display-execute -tckp path/to/trace
```

where `-t` shows the terms of the trace, `-c` show the claims emitted by the PUT, `-k` show the knowledges extracted from the messages and `-p` show the decrypted knowledges.

## Trace triaging

To triage all the traces in the objectives, we provide a Python library to automate grouping traces.

Start by importing the necessary elements from `./tools/differential/diff-analyzer.py`

```python
import sys
from diff_analyzer import (
    BucketCondition,
    NoDiffC,
    AllC,
    AnyC,
    NotC,
    StatusC,
    CheckAgentC,
    TermContainsC,
    ClaimContainsC,
    TermContainsReC,
    StepC,
    InnerKnowledgeC,
    DifferentClaimC,
    KnowledgeContainsC,
    run_triaging,
    KnowledgeDiffC,
)

```

Set the parameters:

```python
# Our first PUT is OpenSSL and our second PUT is wolfSSL
OSSL = 1
WOLF = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "wolfssl580"

# Use 8 threads to do the triaging
PARALLELISM = 8


# Where are the objectives
OBJECTIVE_FOLDER = 'objective'

# Where do we store the triaged objectives
# Could be the same folder
TARGET_FOLDER = 'objective'
```

Now we can write our classification criteria. To do so we create a Python dictionary where the keys are the name of our criterion output folder and the value is the query. Here are some examples:


```python
buckets: dict[str, BucketCondition] = {
    # Check that the trace is a TLS 1.2 trace using `CheckAgentC` condition to
    # access the agent config and check that OpenSSL raises an error containing
    # the string `tls1_set_server_sigalgs:no shared signature algorithms`
    "tls12_no_sigalgs/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(
            OSSL,
            in_error="tls1_set_server_sigalgs:no shared signature algorithms",
        ),
    ),
    # Check that wolfSSL raises an error containing `malformed buffer input error`
    "wolf_malformed_buffer/": StatusC(
        WOLF,
        in_error="malformed buffer input error",
    ),
    # Check that OpenSSL raises an error containing
    # `ossl_statem_client_read_transition` and that the last executed input
    # step contains the `fn_change_cipher_spec` function symbol
    "client_state_transition_CCS/": AllC(
        StatusC(
            OSSL,
            in_error="ossl_statem_client_read_transition",
        ),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
}
```

To understand all the types of query, see their documentation in the `|diff-analyzer` Python module.

To start the triaging:

```python
if __name__ == "__main__":
    run_triaging(
        buckets,
        FIRST_PUT,
        SECOND_PUT,
        source_folder=OBJECTIVE_FOLDER,
        target_folder=TARGET_FOLDER,
        parallelism=PARALLELISM,
    )
```


At the end of the triaging all trace matching a criterion should be in `TARGET_FOLDER/criterion_name`.

The script only evaluate traces directly in `OBJECTIVE_FOLDER` but not in its subfolders.

You can list the number of traces per subfolder using the script `./tools/differential/list_buckets.sh` and reset the triaging (empty the buckets and move the traces in the main objective folder) using `./tools/differential/empty_buckets.sh`.
