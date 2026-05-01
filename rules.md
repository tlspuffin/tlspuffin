Triage the result of a differential fuzzing campaign done using the Puffin fuzzer between OpenSSL and LibreSSL TLS implementations. Analyze those results.

The traces are in the `./objective` folder. Each traces corresponds to an execution of the protocol between one or two TLS agents (client and/or server) which is executed against both Program Under Test (PUT, i.e. OpenSSL and LibreSSL). Each of those traces exhibit differences in its execution on OpenSSL and LibreSSL.


Edit the `./evaluation-ddyf/sort_objectives_ossl_libre.py` triaging script to classify the different objectives into buckets:
- To create a bucket, identify a specific behavior (difference caused by ) by executing a trace then create a new query to capture all traces matching this behavior.
- Each bucket has to contain traces with a unique behavior (e.g. exhibiting the same difference caused by the same succession of actions/function symbols)
- Each bucket must have a precise set of criteria to identify the behavior (error types, function symbols, message type), using only one criterion is not sufficient. Make sure that the difference is not caused by the PUTs finding different problems present in the trace.
- Each bucket must have a Python documentation in the script describing the behavior (type of difference) and its cause (i.e. message flow and function symbol used)
- Each bucket must have a comment tag specifying whether the observed difference is a probable vulnerability (VULN tag), a violation of the TLS specification (RFC) or a difference allowed by the spec (BENIGN). Justify your classification by quoting parts of the TLS 1.3 RFC (available at ./rfc8446.txt) for TLS 1.3 traces and the TLS 1.2 RFC (available at ./rfc5246.txt) for TLS 1.2 traces.

To check those differences use
```bash
./target/release/tlspuffin differential-execute openssl340 libressl421 ./objective/trace_name.trace
```

To view the execution details on one PUT (here openssl340) use
```bash
./target/release/tlspuffin --put openssl340 display-execute ./objective/trace_name.trace -tk
```


display-execute command documentation:
```txt
Executes a trace stored in a file and display information

Usage: tlspuffin display-execute [OPTIONS] <input>

Arguments:
  <input>  The file which stores a trace

Options:
  -s, --max_step <n>                    The step at which to stop
  -t, --show_terms                      Show the terms computed at each input step
  -c, --show_claims                     Show the claims emitted at each input step
  -k, --show_knowledges                 Show the knowledges gathered at each output step
  -r, --show_raw                        Show the computed term as raw hex (eg. for use with netcat)
  -p, --differential_post_computations  Evaluate the post execution terms used in differential fuzzing
  -j, --json                            Export trace execution as JSON
  -C, --disable_security_oracle         Disable the protocol security oracle
  -h, --help                            Print help
```

To run the triaging script use
```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre
```

After a run of the triaging script, you can list the number of traces in each bucket using `./evaluation-ddyf/list_buckets.sh`. And you can reset the objective folder (remove the objectives from the buckets to do another triaging) using `./evaluation-ddyf/empty_buckets.sh`.
After creating a bucket, verify that its content is what you expect. If a bucket contains multiple behavior (e.g. trace with the same differences but caused by two different reasons), split the bucket into more precise ones, empty the buckets and restart triaging.

Examples of previous triaging rules are available in `./evaluation-ddyf/sort_objectives_ossl_wolf.py` (those are not really precise enough but should give good examples of rules) and the query functions are in `./evaluation-ddyf/diff_analyzer.py`. 

The objective folder contains thousands of binary traces so running scripts or commands against all traces is long. To list the directory content use head or tail to reduce the amount of data to work with.

Do not modify any file other than `./evaluation-ddyf/sort_objectives_ossl_libre.py`.
