# Triaging Progress — OpenSSL vs LibreSSL

## Objectif
Trier ~21000 traces de fuzzing différentiel entre OpenSSL 3.4.0 et LibreSSL 4.2.1.

## État d'avancement
- [ ] Phase 1 : Exploration — échantillonner des traces pour identifier les patterns de différences
- [ ] Phase 2 : Création des buckets dans `sort_objectives_ossl_libre.py`
- [ ] Phase 3 : Validation — vérifier que chaque bucket capture le bon comportement
- [ ] Phase 4 : Itération — affiner si des buckets contiennent des comportements mixtes

## Buckets créés
_(à remplir au fur et à mesure)_

## Notes d'exploration

### Famille de traces
Les traces sont nommées `YYYYMMDD-HHMMSSmmm-<hash>.trace`.
Les hashes semblent regrouper des traces de même famille.

### Patterns observés (en cours)

---

## Journal des actions
- [2026-04-30] Lecture des fichiers de référence et documentation
- [2026-04-30] Début de l'exploration des traces (20975 traces au total)
- [2026-04-30] Analyse de ~7000 traces par échantillonnage → identification des patterns principaux
- [2026-04-30] Revue complète de l'architecture triaging-orchestration + liste de correctifs
- [2026-04-30] Application de tous les correctifs — fichiers modifiés :
  - `triaging-orchestration/prompts/explorer.md` — réécrit : double display-execute (OSSL+LIBRE),
    `failing_input_recipe_ossl/libre` (au lieu de `last_input_recipe`), `claims_libre`,
    `knowledge_types_ossl/libre`, correction champs `ossl_error`/`libre_error`, `-k` flag
  - `triaging-orchestration/prompts/classifier.md` — réécrit : nouveaux champs référencés,
    guide de construction des conditions par type de diff
  - `triaging-orchestration/prompts/code_writer.md` — ajout vérification syntaxe + restauration git
  - `triaging-orchestration/ORCHESTRATOR.md` — réécrit : 1500 traces/round1, batches de 30,
    vagues de 10 agents max, `analyzed_traces.txt` mis à jour après validation JSON,
    vérification syntaxe à chaque round, procédure de reprise après interruption,
    critère de stagnation basé sur le taux de classification

## Patterns de différences identifiés (exploration préliminaire)

### Distribution (échantillon ~1000 traces)
| Pattern | Nb (estimé) |
|---|---|
| InnerDiff AlertType1 vs AlertType2 (nombreuses combinaisons) | ~800 |
| Claims DiffTypes: () vs Finished | ~93 |
| Status OSSL_first: ossl_statem_client_read_transition | ~111 |
| Status OSSL_first: ssl3_read_bytes | ~75 |
| Status OSSL_first: final_renegotiate | ~52 |
| Status OSSL_first: tls_read_record records_not_released | ~44 |
| Status OSSL_first: set_client_ciphersuite wrong_cipher | ~41 |
| Status OSSL_first: tls_choose_sigalg | ~40 |
| Status LIBRE_first: CONNECT_CR_SRVR_HELLO | ~103 |
| Status LIBRE_first: ACCEPT_SR_CLNT_HELLO | ~67 |
| KnowledgeDiffTypes Alert vs Handshake | ~30 |
| No diff (flaky) | ~55 |

### Hashes
20 767 hashes uniques sur 20 975 traces → sampling par hash ≅ sampling aléatoire (inutile).
