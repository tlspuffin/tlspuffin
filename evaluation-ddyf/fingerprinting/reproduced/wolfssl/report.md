# wolfssl version fingerprinting -- result

Distinguishing 24 wolfssl releases (5.0.0-5.9.1) over live TCP via DDYF differential-fuzzing probes. LLM-free; reproduce with `run_fingerprint.py --put wolfssl`.

## Decision-tree stats

- Distinguishable clusters (tree leaves): **22**
- Tree depth: **4** -> identify any server by replaying **<= 4 traces**
- Distinct probe traces used: **9** (of 806 confirmed)
- Informative probes (distinguish >= 1 pair): 804

**Live deployment validation:** **14/24** servers recognised, 14/24 consistently across 5 walks, <= 4 traces each. _Honest, deployment-validated number._

## Reliably-distinguishable clusters (22)

Two versions share a cluster iff no probe gives them stably-different live responses.

- **C0** (2): 5.1.0, 5.1.1
- **C1** (2): 5.6.2, 5.6.3
- **C2** (1): 5.0.0
- **C3** (1): 5.2.0
- **C4** (1): 5.2.1
- **C5** (1): 5.3.0
- **C6** (1): 5.4.0
- **C7** (1): 5.5.2
- **C8** (1): 5.5.3
- **C9** (1): 5.5.4
- **C10** (1): 5.6.0
- **C11** (1): 5.6.4
- **C12** (1): 5.6.6
- **C13** (1): 5.7.0
- **C14** (1): 5.7.2
- **C15** (1): 5.7.4
- **C16** (1): 5.7.6
- **C17** (1): 5.8.0
- **C18** (1): 5.8.2
- **C19** (1): 5.8.4
- **C20** (1): 5.9.0
- **C21** (1): 5.9.1

## Pairwise heatmap -- #probes to distinguish each pair

`cell` = number of decision probes played before two versions diverge (`.` = same cluster).

**Distribution over 276 pairs:**

| #probes | pairs |
|---|---:|
| 2 | 42 |
| 3 | 143 |
| 4 | 4 |
| indistinguishable | 87 |

Legend (index -> version): 0=5.0.0, 1=5.1.0, 2=5.1.1, 3=5.2.0, 4=5.2.1, 5=5.3.0, 6=5.4.0, 7=5.5.2, 8=5.5.3, 9=5.5.4, 10=5.6.0, 11=5.6.2, 12=5.6.3, 13=5.6.4, 14=5.6.6, 15=5.7.0, 16=5.7.2, 17=5.7.4, 18=5.7.6, 19=5.8.0, 20=5.8.2, 21=5.8.4, 22=5.9.0, 23=5.9.1

