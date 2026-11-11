# puffin-build

Build helpers of puffin: vendor libraries (`mk_vendor`), C harnesses and PUT bundles. This page documents the
vulnerability catalogue; see the [developer documentation](../docs/docs/developer/build.md) for the build process.

## Vulnerability catalogue

Each vendor directory `vendors/<vendor>/` has a `vulnerabilities.toml`: the known vulnerabilities of the library, the
only source of what builds, tests and the bench know about them. For every entry it gives the affected versions, the
patch removing the bug at each version, and how the bug shows when triggered (its *oracle*). A build of a library knows
from it which bugs it has; an entry has a *witness* trace (or says why not: `no_witness`), and the catalogue test checks
each witness on real executions with and without the patch.

### Entries

The key of an entry is its id: the CVE id, or a local id for bugs without one. Ids use letters, digits, `-`, `_` and
`.` (not `+`, the separator of derived names, and not `all`).

```toml
[CVE-2022-39173]
alias = "BUF"                        # short name (papers, bench)
summary = "stack-buffer-overflow in RefineSuites: ..."
category = "memory"                  # open list: memory, auth-bypass, dos, info-leak, downgrade, ...
cwe = "CWE-787"
cvss = { version = "3.1", score = 7.5, vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source = "nvd" }
affected = "< 5.5.1"                 # library versions with the bug (the presets' `version`)
requires = { postauth = false }      # build options the bug needs (`option()`s of builder.cmake), default: none
capabilities = ["tls13", "tls13_session_resumption"]   # PUT capabilities its witnesses need
put_options = { use_clear = "true" } # PUT options its witnesses run with, default: none
oracle = { kind = "crash", asan = "stack-buffer-overflow" }
top_frames = ["RefineSuites"]        # shown to people, never used to decide
reference = "5.4.0,asan"             # the build `wolfssl:only-CVE-2022-39173` starts from (default below)
check = []                           # more builds for the CI to check the entry on (`5.4.0,no-postauth`)
references = ["https://nvd.nist.gov/vuln/detail/CVE-2022-39173"]

[CVE-2022-39173.find]                # how puffin finds it (informational)
by_puffin = true                     # first found by puffin
since = "<tlspuffin commit>"         # first commit known to find it
features = []                        # cargo features needed
flags = []                           # fuzzer flags needed, e.g. ["--put-use-clear"]
asan = false                         # only detected with ASan
time = { mean_s = 0.0, median_s = 0.0, runs = 10, found = 10, budget_s = 3600.0, cores = 1,
         commit = "<commit>", preset = "<preset>", source = "<where the numbers come from>" }

[[CVE-2022-39173.patches]]           # one table per version range needing its own patch
versions = ">= 4.8.0, < 5.5.1"       # the releases the patch applies to (`mk_vendor check-patches`)
files = ["patches/fix-CVE-2022-39173.patch"]   # applied in order, after the builder's own patches
upstream = "<upstream fix>"
```

Other fields:
- `no_patch = "<reason>"`, `no_witness = "<reason>"`, `no_cvss = "<reason>"`: an entry without patch, witness or CVSS
  says why. Without a patch it cannot be validated by patch differential; without a witness it cannot be checked
  (and may have no oracle).
- `bug_in_harness = true`: a bug of the fuzzing harness, not of the library, keyed by the library versions it shows on
  (`affected`), or by the tlspuffin commits that have it: `affected_commits = "not containing <commit of the fix>"`.
  Such an entry records a bug of past commits, fixed in the tree that holds it: no build of the tree has it and no
  witness can show it (`no_witness` is required, and `no_patch`); the bench names the objectives found on older
  commits after it. Patches of the harness (`target = "harness"`, `commits = ...` instead of `versions`), for a bug of
  the tree's own harness, are reserved: neither the builds nor the catalogue test apply them yet, so the loader refuses
  them rather than accept an entry that would never be checked.
- `replayable = false`: objectives found by fuzzing do not reproduce on their own (e.g. they need earlier state).
- `also_triggers = ["<ID>"]`: other entries the witness is known to trigger too (no overlap warning).
- `witness_versions = "<range>"`: the library versions on which the witnesses reach the bug, when they cannot on every
  affected version; elsewhere their outcome decides nothing (e.g. HEAP's witness sends a 17 KB record that releases
  before 5.4.0 refuse).

**Oracle.** `kind = "crash"` with any of `signal` (e.g. "SIGSEGV"), `asan` (the ASan report type, e.g.
"heap-buffer-overflow", "SEGV", "bad-free"), `panic` (a panic message); or `kind = "claim"` with `violation` (the
message of the security oracle, e.g. "Authentication bypass"). An objective matches when every field the oracle gives
is the objective's; the ASan type is only checked on PUTs built with ASan. Stack frames are never part of it: variants
of one bug reach it through other paths.

**Versions.** Dotted numbers with an optional suffix: letters after the plain version (OpenSSL: `1.0.1` < `1.0.1a` <
... < `1.0.1g`, `0.9.8z` < `0.9.8za`), `-<pre>` before it. A version that does not start with a digit and has none (`master`, `main`; `v5.4.0` is refused) is
newer than every release. Ranges: comparisons (`<`, `<=`, `>`, `>=`, `=`) joined by `,` (and) and `||` (or):
`">= 1.0.0, < 1.0.0p || >= 1.0.1, < 1.0.1k"`.

**CVSS.** One source, one rule: NVD's CVSS v3.1 base score, NIST's primary assessment, or the CNA's v3.1 assessment
shown on NVD when NIST gives none (`source = "cna:<name>"`). Never a v2 or v4.0 score. The vector is stored with the
score and the loader recomputes the score from it.

**Default reference build.** The newest version with the bug; among its builds (presets.toml's), the one with the
fewest fixes (the version's own build rather than an alias), then an ASan one, then the shortest name.

### What the loader refuses

Every build and test loads the catalogue and refuses: unknown fields, invalid ids or ranges, missing patch files, a
patch for a preset's version that is not affected, two patches of an entry for one preset's version, a CVSS score that
does not match its vector, `requires` naming no option of builder.cmake, unknown capabilities, incomplete oracles, an
entry without patch, CVSS or (for a witnessed entry) oracle that does not say why, a `reference` or `check` build
without the bug, builds of presets.toml fixing an unknown entry, one that does not affect them or one without a patch
at their version, names of presets.toml that would read as other names (`-only-`, `-fix-`, `,`, a bug's ID or alias),
aliases of presets.toml breaking the rules of the names (both `m` and `no-m`, `gcov` with `sancov`, an empty or repeated
bug), versions with numbers that do not start with one (`v5.4.0`), and the bugs of past tlspuffin commits
(`affected_commits`) that are not bugs of the harness, give library versions too, or have a witness.

### Builds

A build of `<vendor>:<preset>` has the entries affecting its version with its options, minus the ones of its `fix`
list, whose patches it applies. It records in `.catalogue` (library directory) the state of every entry (active,
fixed, unaffected) with the hashes of the catalogue, of each entry and of its patches; the PUT bundle embeds these
states, and PUTs get the cfgs `<ID> = "<put>"` (active) and `fixed_<ID> = "<put>"`.

`mk_vendor make` builds any name of a build, `<vendor>:<version>[,<modifier>…]` (the canonical form; `mk_vendor
modifiers <vendor>` lists the modifiers, `mk_vendor resolve <vendor>:<build>` shows what a name builds). The library
directory and the PUT are named after the build: the name presets.toml gives that build (a version's own build, an
alias), else the dashed form (its *slug*: `wolfssl540-asan`, `wolfssl540-asan-only-CVE-2022-39173`), so that every
build keeps its name.

| name | builds |
|---|---|
| `wolfssl:5.4.0`, `wolfssl:5.4.0,asan` | the plainest preset of the version (`wolfssl540`), with ASan (`wolfssl540-asan`) |
| `wolfssl:5.4.0,only-BUF` | every other active bug with a patch patched; what BUF needs comes with it (ASan: its oracle is an ASan report): `wolfssl540-asan-only-CVE-2022-39173` |
| `wolfssl:5.4.0,only-SDOS2` | the same for SDOS2, with `no-postauth` (its `requires`): `wolfssl540-asan-no-postauth-only-CVE-2022-38152` |
| `wolfssl:5.4.0,fix-BUF+HEAP`, `wolfssl:5.4.0,fix-all` | these bugs patched; every active bug with a patch patched |
| `wolfssl:only-BUF`, `wolfssl:CVE-2022-39173` | from the bug's reference build (`reference`), only that bug left (the second: always ASan) |
| `wolfssl:wolfssl540-asan-only-CVE-2022-39173` | a preset followed by `-<modifier>`s and `-only-<IDs>`, `-fix-<IDs>`, `-fix-all`: exactly that, nothing implied |

Modifiers: `asan`, `sancov` (on by default: the coverage the fuzzer's feedback reads), `gcov` (implies `no-sancov`),
`llvm_cov`, the builder's options (wolfSSL: `postauth`), each also `no-<modifier>`; bugs by ID or alias, any case,
joined by `+`. Versions as the presets write them, or without their dots when unambiguous (`540`, `111j`); `-` may
replace `,` (`540-asan-only-BUF`). Every spelling of a build gets one canonical name (`5.4.0,only-CVE-2022-39173`) and
one slug.

`mk_vendor list <vendor>:<name> [--json]` shows the state of every entry in a build and the *validation set* of a build
(its `-fix-all` build and one `-only-<ID>` build per active bug with a patch). `mk_vendor list --check [--json]` gives
the builds the CI checks the catalogue on. `mk_vendor check-patches [<vendor>]` dry-runs every patch on the sources of
every version of its range, after the presets.toml patches of that version, alone and with the version's other
patches.

### presets.toml

Each vendor directory has a `presets.toml` (format 2): the library once, the versions tested with the harness, and the
builds named for benchmarks. Every other build is a name (above): no preset per ASan or option variant.

```toml
format = 2

[library]
repo = "https://github.com/wolfSSL/wolfssl.git"     # git sources (url = "<template>": archives, e.g. LibreSSL)
builder = "wolfssl"                                # the builtin builder (builder.cmake)
ref = "v{version}-stable"                          # branch or tag of a version; OpenSSL: rules by range,
                                                   # [{ versions = "< 3.0.0", ref = "OpenSSL_{version_}" }, …]

[versions]                                         # a build per version, named <vendor>{compact}: wolfssl540
"5.4.0" = {}
"master" = { ref = "master" }                      # its own ref, commit, repo, url, hash or name

[modifiers]                                        # every modifier of the vendor's names, its value in a
asan = { default = false, doc = "AddressSanitizer: …" }   # version's build (sancov on, the rest as the builder's
sancov = { default = true, doc = "…" }             # defaults: checked)
postauth = { default = true, doc = "…" }           # an option() of builder.cmake

[aliases]                                          # builds named for benchmarks (their history): a version,
wolfssl540-buf = "5.4.0,fix-CVE-2022-42905"        # modifiers and fix-<ID>+<ID> (IDs of the catalogue)

[[patches]]                                        # applied to every build of these versions, after the
versions = ">= 5.5.2, < master"                    # builder's own patches, before the catalogue's fixes
files = ["patches/claims-AllowClaim-552.patch"]
why = "claims instrumentation: …"
```

Templates: `{version}`, `{version_}` (its dots as `_`), `{compact}` (without dots). Two kinds of patches, two files:
presets.toml's are applied to every build of their versions (instrumentation for tlspuffin, build fixes); the
catalogue's fix a bug, applied only when that bug is fixed (`fix-…`, `only-…`, `fix-all`). Rewrite patterns for "every
version that has this code" (`patch(PATTERN …)`) stay in builder.cmake.

### Witnesses and the catalogue test

A witness is a trace that triggers one entry, written in the DSL of the protocol crate and registered with an
attribute:

```rust
#[puffin::witness("CVE-2022-39173")]
pub fn seed_cve_2022_39173_minimized(server: AgentName) -> Trace<TLSProtocolTypes> { ... }
```

A witness can also be a function returning a `puffin::catalogue::WitnessRun`, whose prelude executions prepare the PUT
state in the same process (see `witness_cve_2022_38153`); `extra = [<capability>, ...]` names capabilities the trace
needs besides its entry's.

`cargo test -p tlspuffin --features cputs --test catalogue` runs the catalogue test on the PUTs of the vendor directory:
- with no PUT at all: every entry has a witness or a `no_witness` reason, every witness names an entry;
- every PUT carries the catalogue state of the source tree (otherwise rebuild it);
- each witness on each PUT of its vendor with the entry's capabilities, judged from the PUT's state. Where the entry is
  the only active bug with a patch (an `-only-<ID>` build), the witness must give an objective matching the oracle.
  Where it and every other bug with a patch are patched (`-fix-all`), it must not: an objective with the entry's own
  signature fails (a broken patch, unless the bugs still active that share it are declared in `also_triggers`), any
  other objective must come from a bug still active (an overlap: a warning unless declared), and a witness none of
  whose executions ran to its end fails (nothing shows the patch works). Elsewhere results are only warned about.

The test prints the matrix of results and writes them as JSON to `$PUFFIN_CATALOGUE_REPORT`. The same check runs from a
binary: `tlspuffin catalogue check`; `tlspuffin witness <ID> --put <put>` runs the witnesses of one entry, and
`tlspuffin execute --outcome <file> <trace>` writes the outcome of executions as JSON.

### Adding a known bug

1. The entry in `vendors/<vendor>/vulnerabilities.toml`, with CVSS from NVD.
2. The patch, in `vendors/<vendor>/patches/`, one per range of releases it applies to; `mk_vendor check-patches
   <vendor>` checks the ranges.
3. The witness, annotated with `#[puffin::witness("<ID>")]`.
4. Locally: `mk_vendor list --check` gives the preset to check it on; build its validation set
   (`mk_vendor make --asan <vendor>:<build>` for each build) and run the catalogue test.

CI then checks it on its own: the catalogue jobs come from the catalogue.
