# Code Writer Agent

## Contexte

Tu travailles sur le projet tlspuffin, un fuzzer de protocole TLS.
Dossier de travail : `/home/nbaffou/dev/tlspuffin/`

Ton rôle : mettre à jour le script de triaging `./evaluation-ddyf/sort_objectives_ossl_libre.py` en ajoutant les nouveaux buckets définis dans le fichier JSON fourni.

---

## Entrées

Nouveaux buckets à ajouter :
{{NEW_BUCKETS_JSON}}

Script existant à modifier :
`./evaluation-ddyf/sort_objectives_ossl_libre.py`

---

## Procédure

### 1. Vérifier la syntaxe du script existant

Avant toute modification :
```bash
python3 -c "import ast; ast.parse(open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()); print('OK')"
```

Si le résultat n'est pas `OK`, restaurer le fichier depuis git avant de continuer :
```bash
git checkout evaluation-ddyf/sort_objectives_ossl_libre.py
```

### 2. Lire le fichier JSON d'entrée et le script existant

Lire `{{NEW_BUCKETS_JSON}}` et lire `./evaluation-ddyf/sort_objectives_ossl_libre.py`.

Ignorer les buckets dont `python_condition` contient `"TODO:"`.

### 3. Pour chaque bucket valide dans le JSON

Ajouter une entrée dans le dictionnaire `buckets` du script.

**Format de chaque entrée :**

```python
    # [TAG] Description courte du comportement
    # RFC §X.X.X: "citation verbatim de la RFC (tronquée si longue)"
    "nom_du_bucket/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="xxx"),
        TermContainsC(OSSL, "fn_yyy", last_input_executed=True),
    ),
```

Où `[TAG]` est l'un de : `[VULN]`, `[RFC]`, `[BENIGN]`, `[UNCLASSIFIED]`.

Si `tag` est `null` dans le JSON, écrire `[UNCLASSIFIED]`.
Si `rfc_quote` est `null`, omettre la ligne RFC.

### 4. Ordre d'insertion

Insérer les nouveaux buckets **avant** toute entrée catch-all existante (entrées avec `TrueC()` ou sans conditions précises comme `"tls12/":` sans `AllC`).

Les buckets avec plus de conditions (`AllC` avec 3+ critères) avant ceux avec moins de conditions.

### 5. Vérifier la syntaxe après modification

```bash
python3 -c "import ast; ast.parse(open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()); print('OK')"
```

Si erreur de syntaxe : la corriger. Si impossible à corriger proprement, restaurer depuis git et signaler le problème :
```bash
git checkout evaluation-ddyf/sort_objectives_ossl_libre.py
```

---

## Structure du script (rappel)

```python
import sys
from .diff_analyzer import (
    BucketCondition, NoDiffC, AllC, AnyC, NotC,
    StatusC, CheckAgentC, TermContainsC, ClaimContainsC,
    TermContainsReC, StepC, InnerKnowledgeC, DifferentClaimC,
    KnowledgeContainsC, run_triaging, KnowledgeDiffC,
)

OSSL = 1
LIBRE = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "libressl421"
PARALLELISM = 10

buckets: dict[str, BucketCondition] = {
    "no_errors/": NoDiffC(),
    # ... nouveaux buckets ici ...
}

if __name__ == "__main__":
    objective_folder = sys.argv[1] if len(sys.argv) > 1 else "objective"
    run_triaging(buckets, FIRST_PUT, SECOND_PUT,
                 source_folder=objective_folder, target_folder=objective_folder,
                 parallelism=PARALLELISM)
```

---

## Contraintes

- Ne modifie **que** `./evaluation-ddyf/sort_objectives_ossl_libre.py`
- Ne change pas les imports, les constantes, ni le bloc `if __name__ == "__main__"`
- Ne change pas les buckets existants
- Ne lis pas les fichiers de traces ni les RFC
- Utilise uniquement les classes importées déjà présentes dans le script
