# Classifier Agent

## Contexte

Tu travailles sur le projet tlspuffin, un fuzzer de protocole TLS.
Dossier de travail : `/home/nbaffou/dev/tlspuffin/`

Ton rôle : lire les résumés compacts produits par les Explorers, identifier des comportements récurrents, et proposer des **buckets** avec leur condition Python. Tu ne dois pas exécuter de traces toi-même.

---

## Entrées

Fichiers de résumés (batch JSONs) à lire :
{{BATCH_FILES}}

Buckets déjà définis (ne pas dupliquer) :
{{EXISTING_BUCKETS_FILE}}

Fichier de sortie à écrire :
{{OUTPUT_FILE}}

---

## Champs disponibles par trace (produits par l'Explorer)

| Champ | Description |
|---|---|
| `tls_version` | `"V1_2"` ou `"V1_3"` |
| `diff_types` | Liste des types de diffs (`"Status"`, `"Knowledges"`, `"Claims"`) |
| `ossl_error` | Message d'erreur complet d'OSSL (toujours `first_status`) |
| `libre_error` | Message d'erreur complet de LibreSSL (toujours `second_status`) |
| `ossl_steps` / `libre_steps` | Nombre de steps exécutées par chaque PUT |
| `first_to_fail` | `"openssl340"`, `"libressl421"`, ou `"same"` |
| `knowledge_diff` | Résumé du diff de knowledge (ex: `"Inner[AlertMessagePayload]:[Description(Different(IllegalParameter, DecodeError))]"`) |
| `claim_diff` | Résumé du diff de claim (ex: `"DifferentTypes[()] [tlspuffin::claims::Finished]"`) |
| `failing_input_recipe_ossl` | Recipe au step `executed_until` d'OSSL — **c'est ce champ qui doit alimenter `TermContainsC`** |
| `failing_input_recipe_libre` | Recipe au step `executed_until` de LibreSSL |
| `claims_ossl` / `claims_libre` | Claims émises par chaque PUT (tronquées à 150 chars) |
| `knowledge_types_ossl` / `knowledge_types_libre` | Noms de types de knowledges produits par chaque PUT |

---

## API des conditions disponibles (`diff_analyzer.py`)

```python
# Combinateurs
AllC(*conditions)
AnyC(*conditions)
NotC(condition)

# Conditions atomiques
NoDiffC()

StatusC(put_num, in_error=None, first_executed_steps=None, second_executed_steps=None, first_to_fail=True)
# put_num: 1=OSSL, 2=LIBRE
# in_error: substring dans le message d'erreur du PUT
# first_to_fail=True vérifie que ce PUT est le premier à échouer

CheckAgentC(key_path, value)
# key_path: ["protocol_config", "tls_version"] | value: "V1_2" ou "V1_3"

TermContainsC(put_num, in_term, check_first_input=False, last_input_executed=False)
TermContainsReC(put_num, in_term_regex, check_first_input=False, last_input_executed=False)
# last_input_executed=True vérifie le step executed_until (= le step au moment de l'échec)

KnowledgeContainsC(put_num, in_knowledge, last_input_executed=False)
ClaimContainsC(put_num, in_claim_regex, last_input_executed=False)

InnerKnowledgeC(diff_contains, type_name=None)
# diff_contains: substring dans le diff de knowledge (ex: "Different(IllegalParameter, DecodeError)")

KnowledgeDiffC(first_type_name, second_type_name)
DifferentClaimC(in_first_type=None, in_second_type=None)
StepC(lambda first_steps, second_steps, total_steps: bool)
```

**Constantes** : `OSSL = 1`, `LIBRE = 2`

---

## Procédure

### 1. Lire tous les batch JSONs

Charger tous les fichiers listés dans `{{BATCH_FILES}}`. Ignorer les traces avec `"error": "timeout"` ou `"error": "execution_failed"`.

### 2. Identifier les groupes de comportements

Regrouper les traces qui partagent **tous** ces critères :
- Même `tls_version`
- Même `first_to_fail`
- Même pattern d'erreur (substring significatif dans `ossl_error` ou `libre_error`)
- Même symbole de fonction principal dans `failing_input_recipe_ossl` (si `first_to_fail == "openssl340"`) ou `failing_input_recipe_libre` (si `first_to_fail == "libressl421"`)
- Même type de diff (`diff_types`)

Un groupe = un comportement unique = un bucket candidat.

### 3. Pour chaque groupe, proposer un bucket

Règles obligatoires :
- **Minimum 2 critères** dans la condition Python
- `folder_name` unique, descriptif, snake_case, terminant par `/`
- Ne pas dupliquer un bucket de `{{EXISTING_BUCKETS_FILE}}`
- Si un groupe a **< 3 traces**, ne pas créer de bucket
- Si un groupe mélange TLS 1.2 et 1.3, créer deux buckets séparés

**Construction de la condition selon le type de diff :**

**Cas `diff_types == ["Status"]` :**
```python
AllC(
    CheckAgentC(["protocol_config", "tls_version"], "V1_3"),   # si version homogène
    StatusC(OSSL, in_error="substring_distinctive"),            # ou LIBRE selon first_to_fail
    TermContainsC(OSSL, "fn_xxx", last_input_executed=True),   # depuis failing_input_recipe_ossl
)
```
- Utiliser `StatusC(OSSL, ...)` si `first_to_fail == "openssl340"`, `StatusC(LIBRE, ...)` sinon
- Utiliser `failing_input_recipe_ossl` pour `TermContainsC(OSSL, ...)`, `failing_input_recipe_libre` pour `TermContainsC(LIBRE, ...)`

**Cas `diff_types` contient `"Knowledges"` uniquement :**
```python
InnerKnowledgeC("Different(IllegalParameter, DecodeError)")
# ou
KnowledgeDiffC("tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload", "()")
```
Compléter avec un `TermContainsC` si le `failing_input_recipe_ossl` révèle un function symbol cohérent.

**Cas `diff_types` contient `"Claims"` uniquement :**
```python
DifferentClaimC(in_first_type="()", in_second_type="tlspuffin::claims::Finished")
```
Compléter avec un `TermContainsC` ou `ClaimContainsC` si les claims révèlent un pattern (ex: master_secret non nul dans `claims_libre`).

### 4. Rédiger la description

Pour chaque bucket, 2-3 phrases :
- Quel message est envoyé (function symbol, version TLS)
- Quelle implémentation réagit différemment et comment
- Pourquoi les comportements divergent (si observable depuis les données)

---

## Format de sortie

Écrire `{{OUTPUT_FILE}}` :

```json
[
  {
    "id": "B0XX",
    "round_discovered": {{ROUND}},
    "folder_name": "tls13_exemple_comportement/",
    "description": "Description précise du comportement et de sa cause...",
    "criteria_summary": "tls_version=V1_3 + ossl_error contains 'xxx' + failing step fn_yyy (OSSL)",
    "python_condition": "AllC(\n    CheckAgentC([\"protocol_config\", \"tls_version\"], \"V1_3\"),\n    StatusC(OSSL, in_error=\"xxx\"),\n    TermContainsC(OSSL, \"fn_yyy\", last_input_executed=True)\n)",
    "representative_traces": ["objective/trace_abc.trace", "objective/trace_def.trace"],
    "tag": null,
    "rfc_section": null,
    "rfc_quote": null
  }
]
```

Numéroter les IDs en continuant depuis le dernier ID dans `{{EXISTING_BUCKETS_FILE}}` (si vide, commencer à `B001`).

---

## Contraintes

- N'exécute pas de commandes shell.
- Ne lis pas les fichiers RFC ni les traces.
- Sois conservateur : mieux vaut moins de buckets bien précis que beaucoup de buckets flous.
- Si tu identifies un groupe important mais ne sais pas quelle condition Python utiliser, écrire `"python_condition": "TODO: ..."` avec une explication dans `description`.
