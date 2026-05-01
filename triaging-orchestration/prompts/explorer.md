# Explorer Agent

## Contexte

Tu travailles sur le projet tlspuffin, un fuzzer de protocole TLS.
Dossier de travail : `/home/nbaffou/dev/tlspuffin/`

Ton rôle : exécuter un lot de 30 traces différentielles et produire un résumé structuré **compact** de chaque trace. Tu ne dois pas interpréter ni regrouper les résultats — juste extraire les faits.

- **Binaire** : `./target/release/tlspuffin`
- **PUT 1 (OSSL)** : `openssl340`
- **PUT 2 (LIBRE)** : `libressl421`

---

## Traces à analyser

{{TRACE_LIST}}

---

## Procédure pour chaque trace

Traite les traces une par une. Pour chaque trace `<path>` :

### 1. Exécuter le diff

```bash
./target/release/tlspuffin differential-execute --json openssl340 libressl421 <path>
```

Extraire depuis la sortie JSON :
- `diff_types` : liste des clés de premier niveau présentes dans chaque objet (ex: `["Status", "Knowledges"]`)
- Si `Status` présent dans le premier objet :
  - `ossl_error` : valeur de `first_status` — **toujours le statut d'OSSL, peu importe qui échoue en premier**
  - `libre_error` : valeur de `second_status` — **toujours le statut de LibreSSL**
  - `ossl_steps` : `first_executed_steps`
  - `libre_steps` : `second_executed_steps`
  - `total_steps` : `total_step`
  - `first_to_fail` : `"openssl340"` si `ossl_steps < libre_steps`, `"libressl421"` si `libre_steps < ossl_steps`, sinon `"same"`
- Si `Knowledges` présent dans le premier objet :
  - Si `InnerDifference` : `knowledge_diff = "Inner[<type_name>]:<diff[:100]>"`
  - Si `DifferentTypes` : `knowledge_diff = "DifferentTypes[<first_type>][<second_type>]"`
- Si `Claims` présent dans le premier objet :
  - Si `DifferentTypes` : `claim_diff = "DifferentTypes[<first_type>][<second_type>]"`
  - Si `InnerDifference` : `claim_diff = "Inner:<diff[:80]>"`

### 2. Exécuter display-execute sur **OSSL**

```bash
./target/release/tlspuffin --put openssl340 display-execute --json -t -k -c <path>
```

Extraire :
- `tls_version` : `execution.agents[0].protocol_config.tls_version` (`"V1_2"` ou `"V1_3"`)
- `eu_ossl` = `execution.executed_until` (index entier de la dernière step exécutée)
- `failing_input_recipe_ossl` : si `execution.steps[eu_ossl].action` est un dict avec clé `"Input"`, extraire `action.Input.recipe[:300]`. Sinon `null`.
- `claims_ossl` : aplatir toutes les listes `claims` de chaque step en une liste de strings tronquées à 150 chars chacune.
- `knowledge_types_ossl` : pour chaque step, pour chaque string dans `knowledges`, extraire le premier mot avant `{` ou `(` — c'est le nom de type (ex: `"AlertMessagePayload"`). Dédupliquer. Liste finale d'au plus 10 types distincts.

### 3. Exécuter display-execute sur **LibreSSL**

```bash
./target/release/tlspuffin --put libressl421 display-execute --json -t -k -c <path>
```

Extraire :
- `eu_libre` = `execution.executed_until`
- `failing_input_recipe_libre` : même logique que pour OSSL mais avec `eu_libre`.
- `claims_libre` : même logique que `claims_ossl`.
- `knowledge_types_libre` : même logique que `knowledge_types_ossl`.

**Si une commande échoue ou dépasse 10 secondes** : mettre les champs correspondants à `null` et continuer.

---

## Format de sortie

Produire un fichier JSON à l'emplacement `{{OUTPUT_FILE}}` contenant une liste d'objets :

```json
[
  {
    "trace": "objective/nom_de_la_trace.trace",
    "tls_version": "V1_3",
    "diff_types": ["Status"],
    "ossl_error": "SSL_ERROR_SSL (1): ...SSL routines:ossl_statem_client_read_transition...",
    "libre_error": "SSL_ERROR_SSL (1): ...SSL routines:CONNECT_CR_SRVR_HELLO...",
    "ossl_steps": 1,
    "libre_steps": 3,
    "total_steps": 8,
    "first_to_fail": "openssl340",
    "knowledge_diff": null,
    "claim_diff": null,
    "failing_input_recipe_ossl": "fn_change_cipher_spec -> Message",
    "failing_input_recipe_libre": "fn_server_hello(...)",
    "claims_ossl": [],
    "claims_libre": ["Finished { master_secret: [0, 0, 0, ..."],
    "knowledge_types_ossl": [],
    "knowledge_types_libre": ["HandshakeMessagePayload"]
  }
]
```

Si une trace échoue complètement (timeout binaire, JSON invalide), inclure quand même un objet avec `"error": "timeout"` ou `"error": "execution_failed"` et tous les autres champs à `null`.

---

## Contraintes

- N'écris rien d'autre que ce fichier JSON de sortie.
- Ne cherche pas à regrouper les traces ou à expliquer les résultats.
- Ne lis pas les fichiers RFC.
- Utilise `python3 -c` ou `jq` pour extraire les champs JSON.
- Si un recipe dépasse 300 chars, le tronquer à 300 chars.
- `claims_ossl` / `claims_libre` : tronquer chaque claim à 150 chars.
- `knowledge_types_*` : au plus 10 types distincts par trace.
