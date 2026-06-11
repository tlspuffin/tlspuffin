# openssl version fingerprinting -- result

Distinguishing 61 openssl releases (3.0.0-3.6.2) over live TCP via DDYF differential-fuzzing probes. LLM-free; reproduce with `run_fingerprint.py --put openssl`.

## Decision-tree stats

- Distinguishable clusters (tree leaves): **11**
- Tree depth: **4** -> identify any server by replaying **<= 4 traces**
- Distinct probe traces used: **4** (of 639 confirmed)
- Informative probes (distinguish >= 1 pair): 615

**Live deployment validation:** **60/61** servers recognised, 60/61 consistently across 5 walks, <= 4 traces each. _Honest, deployment-validated number._

## Reliably-distinguishable clusters (11)

Two versions share a cluster iff no probe gives them stably-different live responses.

- **C0** (24): 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.0.7, 3.0.8, 3.0.9, 3.0.10, 3.0.11, 3.0.12, 3.0.13, 3.0.14, 3.0.15, 3.1.0, 3.1.1, 3.1.2, 3.1.3, 3.1.4, 3.1.5, 3.1.6, 3.1.7
- **C1** (8): 3.2.0, 3.2.1, 3.2.2, 3.2.3, 3.3.0, 3.3.1, 3.3.2, 3.4.0
- **C2** (8): 3.2.5, 3.2.6, 3.3.4, 3.3.5, 3.3.6, 3.4.2, 3.4.3, 3.4.4
- **C3** (6): 3.0.16, 3.0.17, 3.0.18, 3.0.19, 3.0.20, 3.1.8
- **C4** (5): 3.5.1, 3.5.2, 3.5.3, 3.5.4, 3.5.5
- **C5** (3): 3.2.4, 3.3.3, 3.4.1
- **C6** (2): 3.3.7, 3.4.5
- **C7** (2): 3.6.0, 3.6.1
- **C8** (1): 3.5.0
- **C9** (1): 3.5.6
- **C10** (1): 3.6.2

## Pairwise heatmap -- #probes to distinguish each pair

`cell` = number of decision probes played before two versions diverge (`.` = same cluster).

**Distribution over 1830 pairs:**

| #probes | pairs |
|---|---:|
| 2 | 910 |
| 3 | 133 |
| indistinguishable | 787 |

Legend (index -> version): 0=3.0.0, 1=3.0.1, 2=3.0.2, 3=3.0.3, 4=3.0.4, 5=3.0.5, 6=3.0.6, 7=3.0.7, 8=3.0.8, 9=3.0.9, 10=3.0.10, 11=3.0.11, 12=3.0.12, 13=3.0.13, 14=3.0.14, 15=3.0.15, 16=3.0.16, 17=3.0.17, 18=3.0.18, 19=3.0.19, 20=3.0.20, 21=3.1.0, 22=3.1.1, 23=3.1.2, 24=3.1.3, 25=3.1.4, 26=3.1.5, 27=3.1.6, 28=3.1.7, 29=3.1.8, 30=3.2.0, 31=3.2.1, 32=3.2.2, 33=3.2.3, 34=3.2.4, 35=3.2.5, 36=3.2.6, 37=3.3.0, 38=3.3.1, 39=3.3.2, 40=3.3.3, 41=3.3.4, 42=3.3.5, 43=3.3.6, 44=3.3.7, 45=3.4.0, 46=3.4.1, 47=3.4.2, 48=3.4.3, 49=3.4.4, 50=3.4.5, 51=3.5.0, 52=3.5.1, 53=3.5.2, 54=3.5.3, 55=3.5.4, 56=3.5.5, 57=3.5.6, 58=3.6.0, 59=3.6.1, 60=3.6.2

