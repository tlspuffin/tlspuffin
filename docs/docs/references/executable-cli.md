---
title: 'executable CLI'
---

:::warning[Ongoing Work]

This page is currently under development. Information presented here might be incomplete or outdated.

:::

:::tip[What is it?]

Every puffin-based fuzzer (e.g. `tlspuffin`) ships a single executable which can generate seeds, run fuzzing campaigns,
and execute, inspect or plot traces.

```man
`tlspuffin [OPTIONS] [COMMAND]`

Usage: tlspuffin [OPTIONS] [COMMAND]

Commands:
  seed                   Generates seeds to ./seeds
  quick-experiment       Starts a new experiment and writes the results out
  experiment             Starts a new experiment and writes the results out
  differential           Start a differential fuzzing campaign
  differential-experiment Starts a new differential fuzzing experiment and writes the results out
  execute                Executes a trace stored in a file
  display-execute        Executes a trace stored in a file and display information
  differential-execute   Execute a trace on multiple targets, returning the differences
  plot                   Plots a trace stored in a file
  binary-attack          Serializes a trace as much as possible and output it
  tcp                    Executes a trace against a TCP client/server
  mapper                 Debugging information about the mapper
```

:::

:::note

The global options below are **not** accepted after the subcommand: write `tlspuffin --put openssl312 execute <trace>`,
not `tlspuffin execute --put openssl312 <trace>`.

You can precede any command with `RUST_LOG=<info|debug|trace>` to get more logs. Logs can get big (especially with
`trace`), so consider redirecting them to a file.

:::

## Global options

### PUT selection

| Option          | Description                                         |
|-----------------|-----------------------------------------------------|
| `-T, --put <T>` | The PUT to use (default: the fuzzer's default PUT). |
| `-h, --help`    | Print help.                                         |
| `-V, --version` | Print the version.                                  |

### Fuzzing

| Option                 | Description                                                                                                                    |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `-c, --cores <spec>`   | Cores to fuzz on, one client per core, e.g. `0`, `1,2-4,6` or `all` (default: `0`).                                            |
| `-p, --port <n>`       | Port of the broker (default: `1337`).                                                                                          |
| `-i, --max-iters <i>`  | Maximum number of iterations.                                                                                                  |
| `--minimizer`          | Use a minimizer.                                                                                                               |
| `--tui`                | Display the fuzzing logs using the interactive terminal UI.                                                                    |
| `--no-launcher`        | Do not use the convenient launcher.                                                                                            |
| `--put-use-clear`      | Use the clearing functionality instead of recreating PUTs.                                                                     |
| `--stats-interval <n>` | Minimum milliseconds between writes per client (core) for `stats.json` and broker logs (default: `250`, range: `1..=3600000`). |
| `-v, --verbosity <l>`  | Verbosity level for (quick) experiments (default: `Info`).                                                                     |

### Mutations

| Option         | Description                                                 |
|----------------|-------------------------------------------------------------|
| `--with-bit`   | Enable bit-level mutations.                                 |
| `--with-trunc` | Enable truncation of failed trace steps.                    |
| `--step-lock`  | Enable step-locked mutation stacking (disabled by default). |
| `--wo-dy`      | Disable DY mutations.                                       |
| `--wo-focus`   | Disable the focus bit-level mutational stage.               |

:::caution

`--wo-dy` without `--with-bit` is rejected, as it would disable all mutations.

:::

`--with-bit` also controls whether payloads created through bit-level mutations are evaluated by `execute` and
`display-execute`.

## `seed`

Generates the seed traces of the protocol into the `./seeds` directory, one `<name>.trace` file per seed.
The directory is wiped beforehand, so it contains exactly the requested seeds.

```man
`tlspuffin seed [-D] [-c <corpus>,...] [--puts <put>,...]`
```

| Option               | Description                                                                                                                                                         |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-c, --corpus [c]`   | Corpora to generate the seeds from (comma separated names, or `all`; default: `default`). For `tlspuffin`: `default`, `differential_rfc` and `vulnerabilities`.     |
| `--puts [p]`         | PUTs to generate the seeds for (comma separated names; default: the default PUT). Only the seeds supported by all the given PUTs are emitted.                       |
| `-D, --differential` | Generate seeds with restricted PUT descriptor parameters (ciphers, signature algorithms, groups), so that they can be run on several PUTs for differential fuzzing. |

If a seed name appears in several corpora, the first one (in the order given) is kept. Unknown PUTs or corpora are
rejected and the available ones are listed.

```bash
./target/debug/tlspuffin seed --corpus default,vulnerabilities
```

## Fuzzing

Without any subcommand, the executable starts a fuzzing campaign in the current directory. The corpus, the objectives
and the logs are respectively written to `./corpus`, `./objective` and `./log` (the statistics are in
`./log/stats.json`).

```man
`tlspuffin [OPTIONS]`
`tlspuffin [OPTIONS] differential <FIRST_TARGET> <SECOND_TARGET>`
```

The campaign ends on `Ctrl+C`.

### `differential`

Starts a differential fuzzing campaign between two PUTs.

| Argument          | Description                |
|-------------------|----------------------------|
| `<first_target>`  | The first target to fuzz.  |
| `<second_target>` | The second target to fuzz. |

Both targets must exist, otherwise the available PUTs are listed.
See the [differential fuzzing](../developer/differential-fuzzing) page for more details.

### `experiment`

Starts a new fuzzing experiment. Unlike a plain campaign, everything is stored in `./experiments/<title>/`, along with a
README describing the experiment.

```man
`tlspuffin [OPTIONS] experiment -t <title> [-d <description>]`
```

| Option                  | Description                                                                                                            |
|-------------------------|------------------------------------------------------------------------------------------------------------------------|
| `-t, --title <t>`       | Title of the experiment.                                                                                               |
| `-d, --description [d]` | Description of the experiment.                                                                                         |
| `-c, --corpus [c]`      | Corpora used to build the initial seed corpus (comma separated). If not given, `./seeds` is used, otherwise `default`. |

:::caution

The command fails if an experiment with the same (formatted) title already exists.

:::

### `quick-experiment`

Same as `experiment`, but without title nor description. The directory name is generated automatically, and a numeric
suffix is appended if it already exists.

### `differential-experiment`

Same as `experiment`, but for a differential campaign.

| Argument / Option       | Description                    |
|-------------------------|--------------------------------|
| `<first_target>`        | The first target to fuzz.      |
| `<second_target>`       | The second target to fuzz.     |
| `-t, --title <t>`       | Title of the experiment.       |
| `-d, --description [d]` | Description of the experiment. |

## Trace execution

### `execute`

Executes one or several traces, each in a forked process (so that a crash does not lose the coverage of the other
executions).

```man
`tlspuffin execute [OPTIONS] <INPUTS>...`
```

| Argument / Option  | Description                                                              |
|--------------------|--------------------------------------------------------------------------|
| `<inputs>...`      | Trace files or directories containing traces (hidden files are ignored). |
| `-n, --number <n>` | Number of files to execute, starting at the index.                       |
| `-i, --index <i>`  | Index of the first file to execute (default: `0`).                       |
| `-s, --sort`       | Sort files in ascending order by creation date before executing.         |
| `--wo-bit`         | Disable the evaluation of payloads created through bit-level mutations.  |

The exit code describes whether more files are available: `0` if the end of the list was reached, `1` otherwise. This
allows to run large corpora by batches. The modification time (in ms) of the first executed file is printed on the
standard output.

```bash
./target/debug/tlspuffin execute seeds/tlspuffin::tls::seeds::seed_client_attacker.trace
```

### `display-execute`

Executes a trace and displays information about its execution.

```man
`tlspuffin [OPTIONS] display-execute [OPTIONS] <INPUT>`
```

| Argument / Option                             | Description                                                                        |
|-----------------------------------------------|------------------------------------------------------------------------------------|
| `<input>`                                     | The file which stores a trace.                                                     |
| `-s, --max_step <n>`                          | The step at which to stop.                                                         |
| `-t, --show_terms <bool>`                     | Show the terms computed at each input step.                                        |
| `-c, --show_claims <bool>`                    | Show the claims emitted at each input step.                                        |
| `-k, --show_knowledges <bool>`                | Show the knowledge gathered at each output step.                                   |
| `-r, --show_raw <bool>`                       | Show the computed terms as raw hex (e.g. for use with `netcat`).                   |
| `-p, --differential_post_computations <bool>` | Evaluate the post-execution terms used in differential fuzzing (e.g. decryptions). |
| `-j, --json <bool>`                           | Export the trace execution as JSON.                                                |
| `-C, --disable_security_oracle <bool>`        | Disable the protocol security oracle.                                              |

The exit code is `0` if the execution succeeded, `1` otherwise.

### `differential-execute`

Executes a trace on two PUTs and returns the differences between the executions.

```man
`tlspuffin differential-execute [OPTIONS] <FIRST_TARGET> <SECOND_TARGET> <INPUT>`
```

| Argument / Option                     | Description                          |
|---------------------------------------|--------------------------------------|
| `<first_target>`                      | First PUT.                           |
| `<second_target>`                     | Second PUT.                          |
| `<input>`                             | Input trace.                         |
| `-S, --enable-security-oracle <bool>` | Enable the protocol security oracle. |
| `-j, --json <bool>`                   | Export the differences as JSON.      |

The PUT configuration of the trace is uniformised first, and all the agents of the trace (including the ones of prior
traces) are mapped to the given PUTs. The exit code is `0` if there is no difference, `1` otherwise.

### `tcp`

Executes a trace against an external TCP client or server. The first agent of the trace is replaced by a `tcp` PUT.

```man
`tlspuffin tcp [OPTIONS] <INPUT>`
```

| Argument / Option  | Description                                                           |
|--------------------|-----------------------------------------------------------------------|
| `<input>`          | The file which stores a trace.                                        |
| `-c, --cwd [p]`    | The working directory for the binary.                                 |
| `-b, --binary [p]` | The program to start.                                                 |
| `-a, --args [a]`   | The arguments of the program.                                         |
| `-t, --host [h]`   | The host to connect to, or the server host (default: `127.0.0.1`).    |
| `-p, --port [n]`   | The client port to connect to, or the server port (default: `44338`). |

## Trace inspection

### `plot`

Plots a trace stored in a file using Graphviz.

```man
`tlspuffin plot [OPTIONS] <INPUT> <FORMAT> <OUTPUT_PREFIX>`
```

| Argument / Option | Description                                                   |
|-------------------|---------------------------------------------------------------|
| `<input>`         | The file which stores a trace.                                |
| `<format>`        | The format of the plot, `svg` or `pdf`.                       |
| `<output_prefix>` | The prefix of the output files.                               |
| `--multiple`      | Additionally output multiple views, besides the combined one. |
| `--tree`          | Use tree mode in the combined view.                           |

The combined view is written to `<output_prefix>_all.<format>`, and each additional view to
`<output_prefix>_<i>.<format>`.

### `binary-attack`

Serializes the input steps of a trace as much as possible and writes the raw bytes to a file.

```man
`tlspuffin binary-attack <INPUT> <OUTPUT>`
```

| Argument   | Description                               |
|------------|-------------------------------------------|
| `<input>`  | The file which stores a trace.            |
| `<output>` | The file to write the serialized data to. |

### `mapper`

Prints debugging information about the mapper, i.e. the function symbols of the protocol signature (sorted
alphabetically).

```man
`tlspuffin mapper [--path] <COMMAND>`
```

| Command     | Description                                                                                                  |
|-------------|--------------------------------------------------------------------------------------------------------------|
| `symbols`   | Show all function symbols.                                                                                   |
| `signature` | Show all function symbols with their type signatures (parameter types and output type).                      |
| `buildable` | Show, per function symbol, the cost of the cheapest closed term rooted at it, and whether one exists at all. |

| Option   | Description                                                      |
|----------|------------------------------------------------------------------|
| `--path` | Show the full Rust path of each symbol instead of just its name. |
