# CLAUDE.md — Project context for Claude Code sessions

**This project uses the v3 prompt set at `prompts-v3/`.**

If you are a Claude Code session that has been launched **without** `--append-system-prompt`, read `prompts-v3/START_HERE.md` now. It is the entry point.

If you have been launched **with** `--append-system-prompt "$(cat prompts-v3/<ROLE>.md)"` — the recommended invocation — your role-specific instructions are already loaded; this file just provides project context.

## Project at a glance

Differential Dolev-Yao Fuzzing (DDYF) of TLS implementations using **tlspuffin**. Triages the differences between two TLS PUTs (OpenSSL vs LibreSSL in the current campaign) into named buckets, then writes one bug report + one minimal reproducer per identified root cause.

## Key paths

| Path | Contents |
|---|---|
| `prompts-v3/` | Current prompt set. Start with `prompts-v3/START_HERE.md`. |
| `OLD-v2/` | Archived v1 and v2 prompt material (do not use for new work). |
| `evaluation-ddyf/` | Triaging script, Phase 0 metadata producer, helper shell scripts. |
| `objective/` | Fuzzer traces grouped into bucket subfolders. Each trace is co-located with its 3 `metadata_*.log` files. |
| `BUGS/` | Bug-report markdowns + standalone Python reproducers. |
| `vendor/` | Source + compiled binaries of the TLS PUTs being compared (`libressl421/`, `openssl340/`). |
| `target/release/tlspuffin` | The fuzzer binary used by Phase 0 and any on-demand `display-execute` / `differential-execute` calls. |
| `rfc8446.txt`, `rfc5246.txt` | TLS 1.3 and TLS 1.2 RFCs (cite section + line in every bug report). |

## How to determine current campaign state

Before doing anything, check what artifacts exist:
- `find objective -name "*.trace" | wc -l` — number of traces
- `find objective -name "metadata_*.log" | wc -l` — should be 3× trace count if Phase 0 is done
- `grep -c "^\s*\"[^\"]*\":" evaluation-ddyf/sort_objectives_ossl_libre.py` — bucket count
- `ls BUGS/*.md 2>/dev/null | wc -l` — bug-report count
- `ls audit/audit_*_verdict.md 2>/dev/null` — audit-pass artifacts

If a prior campaign is fully present (`BUGS/` populated, `CAMPAIGN_REPORT.md` exists), confirm with the user whether they want a fresh campaign or to extend / re-audit the existing one — do not silently overwrite.

`prompts-v3/START_HERE.md` "Determining campaign state on launch" has the full decision table.

## Hard rules that apply to every Claude Code session in this project

1. **Never pass `-quiet` to `openssl s_server`** — the sanitized OpenSSL 3.4.0 binary at `vendor/openssl340/bin/openssl` crashes (null function pointer, PC=0x0) on any incoming ClientHello when `-quiet` is set. Suppress output via `Popen(..., stdout=DEVNULL, stderr=DEVNULL)` instead.
2. **`vendor/openssl340/bin/openssl` is a UBSan/ASan debug build.** Crashes in it may not reproduce in production. Verify with `/usr/bin/openssl` before assigning a security score to a crash finding.
3. **The Security Gate (`prompts-v3/SECURITY_GATE.md`) is strict for `[VULN]` tagging but not for thinking** — unverified-but-interesting ideas go in "Speculative attack paths" sections, clearly labelled and unscored.
4. **TCP RST and silent close are equivalent at the TLS layer** — both mean "no alert sent" and both are RFC violations when an alert is required.
5. **All artifacts must remain in sync** — bucket name ↔ `BUGS/<root>.md` ↔ `BUGS/reproduce_<root>.py`. See `prompts-v3/NAMING_CONVENTIONS.md` for the exact convention.
