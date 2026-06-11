# wolfssl version fingerprinting -- result

Distinguishing 26 wolfssl releases (5.0.0-5.9.1) over live TCP via DDYF differential-fuzzing probes. LLM-free; reproduce with `run_fingerprint.py --put wolfssl`.

## Decision-tree stats

- Distinguishable clusters (tree leaves): **12**
- Tree depth: **3** -> identify any server by replaying **<= 3 traces**
- Distinct probe traces used: **8** (of 182 confirmed)
- Informative probes (distinguish >= 1 pair): 182

**Live deployment validation:** **26/26** servers recognised, 26/26 consistently across 5 walks, <= 3 traces each. _Honest, deployment-validated number._

## Reliably-distinguishable clusters (12)

Two versions share a cluster iff no probe gives them stably-different live responses.

- **C0** (5): 5.1.0, 5.1.1, 5.2.0, 5.5.0, 5.5.1
- **C1** (4): 5.6.0, 5.6.2, 5.6.3, 5.6.4
- **C2** (3): 5.7.6, 5.8.0, 5.8.2
- **C3** (2): 5.0.0, 5.2.1
- **C4** (2): 5.3.0, 5.4.0
- **C5** (2): 5.5.2, 5.5.3
- **C6** (2): 5.7.2, 5.7.4
- **C7** (2): 5.9.0, 5.9.1
- **C8** (1): 5.5.4
- **C9** (1): 5.6.6
- **C10** (1): 5.7.0
- **C11** (1): 5.8.4

## Pairwise heatmap -- #probes to distinguish each pair

`cell` = number of decision probes played before two versions diverge (`.` = same cluster).

**Distribution over 325 pairs:**

| #probes | pairs |
|---|---:|
| 2 | 202 |
| 3 | 28 |
| indistinguishable | 95 |

Legend (index -> version): 0=5.0.0, 1=5.1.0, 2=5.1.1, 3=5.2.0, 4=5.2.1, 5=5.3.0, 6=5.4.0, 7=5.5.0, 8=5.5.1, 9=5.5.2, 10=5.5.3, 11=5.5.4, 12=5.6.0, 13=5.6.2, 14=5.6.3, 15=5.6.4, 16=5.6.6, 17=5.7.0, 18=5.7.2, 19=5.7.4, 20=5.7.6, 21=5.8.0, 22=5.8.2, 23=5.8.4, 24=5.9.0, 25=5.9.1

