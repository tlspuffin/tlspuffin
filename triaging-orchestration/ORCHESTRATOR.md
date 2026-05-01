# Triaging Orchestrator — Playbook

## Ton rôle

Tu es l'orchestrateur d'une campagne de triaging multi-rounds. Ton travail est de spawner des agents spécialisés, d'interpréter leurs confirmations courtes, et de prendre des décisions sur la suite. **Tu ne lis jamais les traces directement, tu ne lis jamais les RFC.** Ce travail est délégué.

---

## Contexte du projet

- **Dossier racine** : `/home/nbaffou/dev/tlspuffin/`
- **Binaire** : `./target/release/tlspuffin`
- **PUTs** : `openssl340` (PUT 1 = OSSL) et `libressl421` (PUT 2 = LIBRE)
- **Traces à trier** : `./objective/*.trace` (~20 975 traces)
- **Script de triaging** : `./evaluation-ddyf/sort_objectives_ossl_libre.py`
- **API des conditions** : `./evaluation-ddyf/diff_analyzer.py`
- **Exemples de buckets** : `./evaluation-ddyf/sort_objectives_ossl_wolf.py`
- **RFC TLS 1.3** : `./rfc8446.txt` | **RFC TLS 1.2** : `./rfc5246.txt`

Lancer le triaging :
```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre
```
Compter les buckets :
```bash
./evaluation-ddyf/list_buckets.sh
```
Réinitialiser les buckets (vider les dossiers pour relancer) :
```bash
./evaluation-ddyf/empty_buckets.sh
```

---

## Règle fondamentale : modèle et parallélisme des agents

**Tous les sous-agents doivent être spawned avec le modèle `haiku`** (Explorer, Classifier, RFC Lookup, Code Writer).

**Maximum 10 agents en parallèle.**

**Ne jamais spawner plus de 10 agents simultanément.** Si un round nécessite N agents (ex: 50 Explorers), les lancer en vagues de 10 :
- Vague 1 : agents 0–9 → attendre la fin de tous → valider → continuer
- Vague 2 : agents 10–19 → attendre → valider → continuer
- ...

Chaque vague est lancée en **un seul message** avec tous ses agents en `background=true`. Ne pas passer à la vague suivante avant d'avoir reçu les confirmations de la vague courante.

---

## Structure des fichiers d'état

Tout l'état est dans `./triaging-orchestration/state/`. Ce répertoire persiste entre les rounds.

```
state/
├── progress.json
├── analyzed_traces.txt        # traces confirmées analysées (1 chemin par ligne)
├── buckets_draft.json
├── final_buckets.json         # rempli en phase finale
├── round_1/
│   ├── sample.txt             # toutes les traces échantillonnées ce round
│   ├── batches/
│   │   ├── batch_00.txt      # liste des 30 traces pour ce batch
│   │   ├── batch_00.json     # sortie de l'Explorer (présent si terminé et valide)
│   │   ├── batch_01.txt
│   │   ├── batch_01.json
│   │   └── ...
│   └── classifier_output.json
├── round_2/
│   └── ...
```

### Format : `progress.json`
```json
{
  "current_round": 1,
  "total_traces": 20975,
  "traces_analyzed_so_far": 0,
  "buckets_defined": 0,
  "unclassified_after_last_run": 20975,
  "rejected_buckets": []
}
```

### Format : `buckets_draft.json`
```json
[
  {
    "id": "B001",
    "round_discovered": 1,
    "folder_name": "nom_du_bucket/",
    "description": "Description précise du comportement et de sa cause",
    "criteria_summary": "ossl_error X + tls_version V1_3 + failing step fn_yyy (OSSL)",
    "python_condition": "AllC(\n    CheckAgentC([\"protocol_config\", \"tls_version\"], \"V1_3\"),\n    StatusC(OSSL, in_error=\"...\"),\n    TermContainsC(OSSL, \"fn_yyy\", last_input_executed=True)\n)",
    "representative_traces": ["objective/trace_abc.trace"],
    "tag": null,
    "rfc_section": null,
    "rfc_quote": null
  }
]
```

---

## Procédure : initialisation (Round 1 uniquement)

```bash
mkdir -p triaging-orchestration/state/round_1/batches
```

1. Compter les traces : `ls objective/*.trace | wc -l` → écrire dans `progress.json`
2. Créer `state/analyzed_traces.txt` (vide)
3. Créer `state/buckets_draft.json` = `[]`
4. Vérifier la syntaxe du script :
   ```bash
   python3 -c "import ast; ast.parse(open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()); print('OK')"
   ```
   Si KO → `git checkout evaluation-ddyf/sort_objectives_ossl_libre.py`
5. Passer à la procédure de round.

---

## Procédure : un round complet

### Étape 0 — Vérification préliminaire (à chaque round)

```bash
python3 -c "import ast; ast.parse(open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()); print('OK')"
```
Si KO → `git checkout evaluation-ddyf/sort_objectives_ossl_libre.py` avant de continuer.

### Étape 1 — Échantillonnage

**Round 1** : sélectionner **300 traces** (toutes les ~70 traces).
**Rounds suivants** : sélectionner **300 traces** en excluant les traces déjà dans `analyzed_traces.txt`.

```bash
# Round 1 : toutes les 70 traces
ls objective/*.trace | awk 'NR % 70 == 0' > triaging-orchestration/state/round_1/sample.txt

# Rounds suivants : exclure les déjà vus, calculer l'intervalle pour prendre environ 300 traces
ls objective/*.trace | grep -v -F -f triaging-orchestration/state/analyzed_traces.txt \
  | awk 'NR % [X] == 0' > triaging-orchestration/state/round_N/sample.txt
```

Découper `sample.txt` en batches de **30 traces** et écrire chaque `batch_MM.txt` :
```bash
split -l 30 -d --additional-suffix=.txt \
  triaging-orchestration/state/round_N/sample.txt \
  triaging-orchestration/state/round_N/batches/batch_
# Renommer batch_00.txt, batch_01.txt, ... si nécessaire selon le format de split
```

**Ne pas encore mettre à jour `analyzed_traces.txt`** — cela se fait après validation des JSONs.

### Étape 2 — Lancer les Explorers

Calculer le nombre total de batches : `ls triaging-orchestration/state/round_N/batches/*.txt | wc -l`

**Lancer tous les agents dans un seul message** avec `background=true` et `model=haiku` :

```
Modèle : haiku
Lis et suis les instructions dans triaging-orchestration/prompts/explorer.md.
Tes entrées spécifiques :
- TRACE_LIST: <contenu de batch_MM.txt, un chemin par ligne>
- OUTPUT_FILE: triaging-orchestration/state/round_N/batches/batch_MM.json
```

Attendre les confirmations de fin de **tous** les agents de la vague avant de passer à la suite.

**Une fois la vague terminée — validation :**

Pour chaque `batch_MM.json` de la vague :
```bash
python3 -c "import json; json.load(open('triaging-orchestration/state/round_N/batches/batch_MM.json')); print('OK')" 2>&1
```
- Si `OK` : ajouter les traces de `batch_MM.txt` à `analyzed_traces.txt`
- Si erreur JSON : noter le batch comme invalide. Re-spawner un Explorer pour ce batch **dans la prochaine vague** (ou immédiatement si la vague en cours est terminée), en utilisant les mêmes traces de `batch_MM.txt`.

### Étape 3 — Lancer le Classifier

Spawner un agent `general-purpose` (foreground) avec `model=haiku` :

```
Modèle : haiku
Lis et suis les instructions dans triaging-orchestration/prompts/classifier.md.
Tes entrées spécifiques :
- BATCH_FILES: triaging-orchestration/state/round_N/batches/batch_00.json, batch_01.json, ... (tous les JSONs valides)
- EXISTING_BUCKETS_FILE: triaging-orchestration/state/buckets_draft.json
- OUTPUT_FILE: triaging-orchestration/state/round_N/classifier_output.json
- ROUND: N
```

Attendre le résultat. Lire `classifier_output.json`.

**Vérifier chaque bucket proposé :**
1. A au moins **deux critères** dans `python_condition`
2. `folder_name` unique et terminant par `/`
3. `representative_traces` non vide
4. Ne chevauche pas un bucket dans `buckets_draft.json`

Buckets valides → ajouter à `buckets_draft.json`.
Buckets invalides → noter dans `progress.json` sous `rejected_buckets`, ne pas ajouter.

### Étape 4 — Mettre à jour le script et lancer le triaging

Spawner un agent `general-purpose` (foreground) avec `model=haiku` :

```
Modèle : haiku
Lis et suis les instructions dans triaging-orchestration/prompts/code_writer.md.
Tes entrées spécifiques :
- NEW_BUCKETS_JSON: triaging-orchestration/state/round_N/classifier_output.json
```

Quand l'agent confirme, exécuter le triaging :

```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre
./evaluation-ddyf/list_buckets.sh
```

Compter les traces non classées :
```bash
ls objective/*.trace 2>/dev/null | wc -l
```

### Étape 5 — Décider de la suite

Mettre à jour `progress.json` (`unclassified_after_last_run`, `traces_analyzed_so_far`, `buckets_defined`, `current_round`).

| Condition                                                                                        | Action                                                    |
|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| > 1 000 traces non classées                                                                      | Lancer un nouveau round                                   |
| 200–1 000 traces non classées                                                                    | 1 round supplémentaire avec 200 traces ciblées            |
| < 200 traces non classées                                                                        | Passer à la **Phase Finale**                              |
| Stagnation : < 3 nouveaux buckets ce round **ET** < 5 % des traces non classées triées ce round | Passer à la **Phase Finale** même si des traces restent   |

---

## Phase Finale : RFC Lookup + Code Writer final

### RFC Lookup (en vagues de 10)

Pour chaque bucket dans `buckets_draft.json` dont `tag == null`, spawner un agent `general-purpose` en `background=true` et `model=haiku` :

```
Modèle : haiku
Lis et suis les instructions dans triaging-orchestration/prompts/rfc_lookup.md.
Tes entrées spécifiques :
- BUCKET_SPEC: <objet JSON du bucket : id + description + criteria_summary + python_condition>
```

Lancer **par vagues de 10 maximum**. Attendre chaque vague avant la suivante.

Pour chaque résultat reçu : mettre à jour le bucket correspondant dans `buckets_draft.json` avec `tag`, `rfc_section`, `rfc_quote`.

Copier `buckets_draft.json` → `state/final_buckets.json`.

Une fois une vague fini, vérifier si une autre doit être lancée:
- Si oui alors retourner au début de la phase RFC Lookup et lancer la vague suivante.
- Si non alors passer à la phase suivante.

### Code Writer Final

Spawner un agent `general-purpose` (foreground) avec `model=haiku` :

```
Modèle : haiku
Lis et suis les instructions dans triaging-orchestration/prompts/code_writer.md.
Tes entrées spécifiques :
- NEW_BUCKETS_JSON: triaging-orchestration/state/final_buckets.json
```

Vérifier la syntaxe :
```bash
python3 -c "import ast; ast.parse(open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()); print('OK')"
```

Lancer un triaging final de validation :
```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre
./evaluation-ddyf/list_buckets.sh
```

---

## Procédure de reprise (si interruption en cours de round)

Si la session a été interrompue (manque de crédits, timeout), reprendre ainsi :

### 1. Identifier l'état courant
```bash
cat triaging-orchestration/state/progress.json
```
→ note `current_round` = N.

### 2. Vérifier la syntaxe du script
```bash
python3 -c "import ast; ast.parse(open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()); print('OK')"
```
Si KO → `git checkout evaluation-ddyf/sort_objectives_ossl_libre.py`

### 3. Identifier les batches à relancer
```bash
# Lister les batch_MM.txt existants (= batches planifiés)
ls triaging-orchestration/state/round_N/batches/*.txt

# Pour chaque batch_MM.txt, vérifier si batch_MM.json existe et est valide
for f in triaging-orchestration/state/round_N/batches/batch_*.txt; do
    base="${f%.txt}"
    if python3 -c "import json; json.load(open('${base}.json'))" 2>/dev/null; then
        echo "OK: ${base}.json"
    else
        echo "MISSING/INVALID: ${base}.json → à relancer"
    fi
done
```

### 4. Re-spawner les Explorers manquants

Pour chaque batch invalide/manquant, re-spawner un Explorer avec les traces du `.txt` correspondant.
Lancer une vague avec les explorer manquants. Valider les JSONs. Mettre à jour `analyzed_traces.txt`.

### 5. Continuer depuis l'Étape 3 (Classifier)

Une fois tous les batch JSONs valides, reprendre à l'Étape 3 du round courant.

---

## Règles de qualité des buckets

Avant d'accepter un bucket du `classifier_output.json` :

1. Au moins **deux critères** dans `python_condition` (un seul `StatusC` est insuffisant)
2. `folder_name` unique, en snake_case, terminant par `/`
3. `representative_traces` non vide
4. Pas de chevauchement avec un bucket existant dans `buckets_draft.json`

---

## Résumé du flux de tokens

| Agent                  | Modèle | Ce qu'il reçoit               | Ce qu'il renvoie à l'orchestrateur                        |
|------------------------|--------|-------------------------------|-----------------------------------------------------------|
| Explorer (×~10/round)  | haiku  | 30 chemins de traces          | `"Done: écrit dans batch_MM.json"`                        |
| Classifier (×1/round)  | haiku  | Chemins vers batch JSONs      | `"N nouveaux buckets, écrit dans classifier_output.json"` |
| RFC Lookup (×1/bucket) | haiku  | 1 spec de bucket              | Tag + quote + section RFC                                 |
| Code Writer (×1/round) | haiku  | Chemin vers JSON de buckets   | `"Script mis à jour"`                                     |

Tu ne gardes en contexte que ces confirmations courtes, **jamais les données brutes**.
