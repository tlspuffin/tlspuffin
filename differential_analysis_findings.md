# Analyse différentielle OpenSSL 3.4.0 vs LibreSSL 4.2.1 — Résultats et buckets

## Contexte

Campagne de fuzzing différentiel entre `openssl340` (PUT 1) et `libressl421` (PUT 2).
**20 975 traces** dans `./objective/`, toutes générées le 28-29 avril 2026.
Binaire : `./target/release/tlspuffin`

Les traces mélangent des agents TLS 1.2 et TLS 1.3. La version est configurée dans
`execution.agents[0].protocol_config.tls_version` (`"V1_2"` ou `"V1_3"`).

---

## Distribution globale des patterns (échantillon ~2000 traces)

Obtenu en exécutant `differential-execute --json` sur une trace toutes les 10.

### Erreurs de statut — OSSL échoue en premier

| Fonction d'erreur OSSL                         | Nb traces (estimé sur 20 975) |
|-------------------------------------------------|-------------------------------|
| `ossl_statem_client_read_transition`            | ~1 100                        |
| `ssl3_read_bytes`                               | ~750                          |
| `final_renegotiate`                             | ~520                          |
| `tls_read_record` (records not released)        | ~440                          |
| `set_client_ciphersuite` (wrong cipher)         | ~410                          |
| `tls_choose_sigalg`                             | ~400                          |
| `tls_collect_extensions` (bad extension)        | ~90                           |
| `tls1_set_server_sigalgs`                       | ~60                           |
| `tls_parse_ctos_sig_algs`                       | ~30                           |

### Erreurs de statut — LibreSSL échoue en premier

| Fonction d'erreur LibreSSL                      | Nb traces (estimé) |
|-------------------------------------------------|--------------------|
| `CONNECT_CR_SRVR_HELLO`                         | ~1 030             |
| `ACCEPT_SR_CLNT_HELLO`                          | ~670               |
| `ACCEPT_SR_FINISHED`                            | ~70                |
| `ACCEPT_SR_KEY_EXCH`                            | ~40                |

### Différences de knowledges (BothAlert — alert types différents)

| Combinaison d'alertes                                       | Nb traces (estimé) |
|------------------------------------------------------------|--------------------|
| `Different(IllegalParameter, DecodeError)`                  | ~1 860             |
| `Different(IllegalParameter, ProtocolVersion)`              | ~650               |
| `Different(HandshakeFailure, IllegalParameter)`             | ~400               |
| `Different(MissingExtension, IllegalParameter)`             | ~380               |
| `Different(IllegalParameter, HandshakeFailure)`             | ~360               |
| `Different(HandshakeFailure, DecodeError)`                  | ~340               |
| `Different(HandshakeFailure, MissingExtension)`             | ~330               |
| `Different(DecodeError, HandshakeFailure)`                  | ~270               |
| `Different(IllegalParameter, MissingExtension)`             | ~220               |
| `Different(HandshakeFailure, UnsupportedExtension)`         | ~160               |
| `Different(UnexpectedMessage, IllegalParameter)`            | ~150               |
| `Different(UnsupportedExtension, IllegalParameter)`         | ~130               |
| `Different(UnsupportedExtension, ProtocolVersion)`          | ~120               |
| `Different(DecodeError, ProtocolVersion)`                   | ~110               |
| Autres combinaisons rares                                   | ~200               |

### Différences de types de knowledges (messages de types différents)

| Combinaison                                    | Nb traces (estimé) |
|------------------------------------------------|--------------------|
| `AlertMessagePayload` vs `()`                  | ~300               |
| `AlertMessagePayload` vs `HandshakeMessagePayload` | ~80           |

### Différences de claims

| Pattern                            | Nb traces (estimé) |
|------------------------------------|--------------------|
| `()` vs `tlspuffin::claims::Finished` (LibreSSL atteint Finished, OSSL non) | ~930 |
| `tlspuffin::claims::Finished` vs `()` (OSSL atteint Finished, LibreSSL non) | ~10  |

### Pas de différence (flaky)

~550 traces sur 20 975 (≈ 2,6 %).

---

## Analyse détaillée par catégorie

### Catégorie 1 — OSSL client read transition (`ossl_statem_client_read_transition`)

**TLS version** : V1_3 principalement.

**Function symbols au step échoué :**
- `fn_change_cipher_spec` (~215 cas) : un CCS est injecté comme premier message vers le client TLS 1.3, avant tout ServerHello.
- `fn_append_flight` (~24 cas) : variante avec un vol de messages injecté.

**Ce qui se passe :** le client OSSL (TLS 1.3) reçoit un CCS ou un autre message hors-séquence avant d'avoir reçu un ServerHello. OSSL le rejette immédiatement avec "unexpected message". LibreSSL continue et échoue beaucoup plus tard (3+ steps après) avec "wrong ssl version" ou une autre erreur liée à la tentative de traitement du ServerHello qui suit.

**Classification probable :** BENIGN — les deux rejettent, mais à des étapes différentes. RFC 8446 §D.4 dit que les CCS doivent être silencieusement ignorés en TLS 1.3 dans certains contextes, mais pas comme premier message sans ServerHello préalable. OSSL est plus strict.

**Trace représentative :** `./objective/20260428-214538925-3eadb813cbe7aa83.trace`

---

### Catégorie 2 — OSSL ssl3_read_bytes unexpected message

**TLS version** : V1_3.

**Function symbols au step échoué :**
- `fn_alert_close_notify` (~103 cas) : un close_notify est injecté hors-séquence.
- `fn_append_flight` (~50 cas) : vol de messages injecté en dehors du bon état.
- `fn_application_data`, `fn_coalesced_flight` (rares).

**Ce qui se passe :** OSSL reçoit un close_notify ou un message de données dans un état où il ne l'attend pas, et échoue avec `ssl3_read_bytes:unexpected message`. LibreSSL continue pour 5 à 8 steps supplémentaires avant d'échouer à son tour (erreur différente, souvent liée au déchiffrement ou à un KeyShare manquant).

**Trace représentative :** `./objective/20260428-220727952-9276eab91e67dd31.trace`

---

### Catégorie 3 — OSSL renegotiation refusée (`final_renegotiate`)

**TLS version** : V1_2.

**Ce qui se passe :** dans un contexte TLS 1.2, la trace envoie d'abord un `fn_client_hello` au client (step 1), puis un `fn_server_hello` (step 2). OSSL interprète le ServerHello reçu comme une tentative de renégociation et la refuse immédiatement avec `final_renegotiate:unsafe legacy renegotiation disabled`. LibreSSL accepte le ServerHello et continue, échouant plus tard au step 3 lors de la vérification du certificat (`CONNECT_CR_CERT:peer did not return a certificate`).

**Classification probable :** RFC — RFC 5746 exige la renégociation sécurisée. OSSL la refuse correctement si l'extension `renegotiation_info` est absente. LibreSSL est plus permissif et tente de continuer.

**Trace représentative :** `./objective/20260428-220213441-0a4b8a2d826c7dd9.trace`

---

### Catégorie 4 — OSSL records not released (`tls_read_record`)

**TLS version** : V1_2.

**Function symbols au step échoué :**
- `fn_decrypt_handshake_flight` (~21 cas)
- `fn_alert_close_notify` (~16 cas) : un close_notify est envoyé, puis d'autres messages arrivent.
- `fn_append_flight` (~4 cas), `fn_change_cipher_spec` (~3 cas), `fn_certificate13` (~3 cas).

**Ce qui se passe :** après réception d'un `fn_alert_close_notify`, la couche record d'OSSL considère que les records précédents ne sont pas libérés, et refuse de traiter le message suivant. LibreSSL continue et échoue beaucoup plus tard sur une variable non trouvée dans l'évaluateur.

**Trace représentative :** `./objective/20260428-221353388-0b5e10f3aedd10cd.trace`

---

### Catégorie 5 — OSSL wrong cipher (`set_client_ciphersuite`)

**TLS version** : V1_2 (config agent), mais les traces utilisent souvent des messages TLS 1.3.

**Ce qui se passe :** un `fn_server_hello` avec une cipher suite incorrecte (changée par rapport au premier ServerHello ou à la HRR) est envoyé au client. OSSL le rejette avec `set_client_ciphersuite:wrong cipher returned`. LibreSSL continue et tente de vérifier le certificat, échouant 2 steps plus tard.

**Remarque :** ce pattern est similaire au bucket `hrr_changing_cipher` et `wrong_cipher` du script wolf. Applicable ici pour TLS 1.2.

**Trace représentative :** `./objective/20260428-221721485-bb682f61383a1378.trace`

---

### Catégorie 6 — OSSL signature algorithm (`tls_choose_sigalg`)

**TLS version** : V1_2.

**Function symbols :** `fn_fill_binder` (combiné avec `fn_hello_retry_request_random` dans le ClientHello).

**Ce qui se passe :** la trace utilise `fn_fill_binder` enveloppant un `fn_client_hello` qui contient `fn_hello_retry_request_random` comme random (valeur magique TLS 1.3). OSSL tente de calculer le binder et échoue dès le step 0 avec `tls_choose_sigalg:no suitable signature algorithm`. LibreSSL tente de traiter le ClientHello et échoue au step 1 avec `ACCEPT_SR_KEY_EXCH:unexpected message`.

**Trace représentative :** `./objective/20260428-215536521-ee1c09423f8851cc.trace`

---

### Catégorie 7 — LibreSSL CONNECT_CR_SRVR_HELLO

LibreSSL client échoue en attendant le ServerHello. Trois sous-patterns selon le function symbol.

#### 7a — `fn_hello_request` (~87 cas)

**Ce qui se passe :** un `fn_hello_request` (message TLS 1.2 de renégociation serveur→client) est injecté comme premier message vers le client LibreSSL. LibreSSL le rejette immédiatement avec `CONNECT_CR_SRVR_HELLO:sslv3 alert unexpected message` au step 0. OSSL continue et échoue plus tard (step 1) avec `tls_post_process_client_hello:no shared cipher`.

**Trace représentative :** `./objective/20260428-224741706-ee14ceadc1a49f4a.trace`

#### 7b — `fn_append_flight` (~53 cas)

**Ce qui se passe :** un vol de messages est injecté dans le client LibreSSL avant qu'il ait établi la session. LibreSSL échoue au step 1 avec `CONNECT_CR_SRVR_HELLO:sslv3 alert unexpected message`. OSSL échoue différemment (erreur de déchiffrement, KeyShare non trouvé) beaucoup plus tard.

#### 7c — `fn_empty_handshake_message` (~39 cas)

**Ce qui se passe :** un message de handshake vide est envoyé au client LibreSSL. LibreSSL rejette avec `CONNECT_CR_SRVR_HELLO`. OSSL continue.

---

### Catégorie 8 — LibreSSL ACCEPT_SR_CLNT_HELLO

LibreSSL serveur échoue en traitant le ClientHello. Deux sous-patterns principaux.

#### 8a — `fn_empty_handshake_message` (~91 cas)

**Ce qui se passe :** un message de handshake vide est envoyé au serveur LibreSSL. LibreSSL le rejette avec `ACCEPT_SR_CLNT_HELLO:sslv3 alert unexpected message`. OSSL retourne une erreur d'évaluation (`Unable to find variable`).

**Trace représentative :** `./objective/20260428-223520356-1b970bd9cafc2fd6.trace`

#### 8b — `fn_client_hello` (~51 cas)

**TLS version :** V1_3.

**Ce qui se passe :** un `fn_client_hello` contenant une ProtocolVersion lue depuis l'output d'un agent (potentiellement TLS 1.2) est envoyé au serveur LibreSSL TLS 1.3. LibreSSL rejette avec `ACCEPT_SR_CLNT_HELLO:tlsv1 alert protocol version`. OSSL continue (4 steps de plus) et échoue sur un déchiffrement.

**Trace représentative :** `./objective/20260428-220949822-6251cc2123f5a13d.trace`

---

### Catégorie 9 — LibreSSL ACCEPT_SR_FINISHED (OSSL réussit !)

**TLS version :** V1_3. **Nb traces estimé :** ~70.

**Ce qui se passe :** c'est le cas le plus intéressant. La trace est une séquence valide :
- Step 0 : Output (client envoie ClientHello)
- Step 1 : injection d'un `MessageFlight` depuis l'output de l'agent 0 (le serveur a déjà produit sa réponse)
- Steps 2–3 : `fn_append_flight(fn_new_flight, fn_alert_close_notify)` — deux close_notify successifs

**OSSL :** exécute les 5 steps sans erreur. `executed_until = 5`. Deux close_notify acceptés.

**LibreSSL :** échoue au step 3 avec `ACCEPT_SR_FINISHED:sslv3 alert unexpected message`. Après avoir traité le premier close_notify (step 2), LibreSSL considère la connexion fermée et rejette le deuxième close_notify (step 3).

**Classification probable :** BENIGN — RFC 8446 §6.1 dit "Any data received after a closure alert has been received MUST be ignored." OSSL est donc plus conforme (il ignore le second close_notify), LibreSSL est plus strict mais les deux comportements sont défendables.

**Trace représentative :** `./objective/20260428-234410869-aba16df0dd78e6cd.trace`

---

### Catégorie 10 — BothAlert : types d'alertes différents (InnerDiff)

Les deux PUTs génèrent une alerte, mais avec des types différents. C'est la catégorie la plus peuplée (~6 000 traces estimées au total).

**Cause commune :** les deux PUTs rejettent le même message malformé mais choisissent des alertes différentes selon leur ordre de validation interne.

**Function symbols les plus fréquents au step échoué :**
- `fn_fill_binder` en TLS 1.2 (~486 cas pour `IllegalParameter vs DecodeError`)
- `fn_client_hello` en TLS 1.3 (~364 cas pour `IllegalParameter vs DecodeError`)

Ces deux sous-patterns sont **distincts** et doivent être deux buckets séparés.

**Détail des combinaisons :**

| Alerte OSSL → Alerte LibreSSL       | Function symbol principal | TLS | Note |
|-------------------------------------|--------------------------|-----|------|
| `IllegalParameter → DecodeError`    | `fn_fill_binder` (V1.2) ou `fn_client_hello` (V1.3) | mixte | Plus fréquent |
| `IllegalParameter → ProtocolVersion`| `fn_client_hello` (V1.3) ou `fn_server_hello` (V1.3) | V1.3 | |
| `HandshakeFailure → IllegalParameter` | `fn_client_hello` ou `fn_fill_binder` | mixte | |
| `MissingExtension → IllegalParameter` | `fn_client_hello` (V1.3) | V1.3 | OSSL plus précis |
| `HandshakeFailure → DecodeError`    | `fn_client_hello` ou `fn_server_key_exchange` | mixte | |
| `HandshakeFailure → MissingExtension` | `fn_client_hello` | V1.3 | |
| `UnexpectedMessage → IllegalParameter` | `fn_fill_binder` | V1.2 | |

**Classification générale :** BENIGN pour la majorité. Les deux implémentations rejettent le message malformé mais choisissent des alertes différentes selon leur ordre de validation. Aucune n'accepte ce qu'elle devrait rejeter.

**Exception possible :** `MissingExtension → IllegalParameter` — OSSL retourne `MissingExtension` qui est plus précis per RFC 8446 §8.2. LibreSSL retourne `IllegalParameter` qui est moins précis. Cela pourrait être classifié RFC (violation mineure de LibreSSL).

---

### Catégorie 11 — KnowledgeDiffTypes : Alert vs () et Alert vs Handshake

**Alert vs ()** (~300 cas) : OSSL envoie une alerte, LibreSSL ne produit rien (ou vice versa). L'un des PUTs traite silencieusement un message que l'autre rejette avec alerte.

**Alert vs Handshake** (~80 cas) : OSSL envoie une alerte, LibreSSL continue avec un message de handshake. Le PUT qui envoie un handshake au lieu d'une alerte est potentiellement problématique.

Ces catégories nécessitent une analyse plus fine des function symbols pour créer des buckets précis.

---

### Catégorie 12 — Claims DiffTypes : LibreSSL atteint Finished

**Nb traces :** ~930. Agent 0 ou 1 selon les traces.

**Ce qui se passe :** LibreSSL émet un claim `tlspuffin::claims::Finished` qu'OSSL n'émet pas. **Important :** dans les traces observées, le claim Finished de LibreSSL contient un `master_secret` à **tous zéros** `[0, 0, 0, ...]`. Ce n'est pas une vraie complétion de handshake avec des clés réelles.

**Contexte d'un cas observé :** TLS 1.2, step 1 = `fn_client_hello` avec `fn_protocol_version13` (version incorrecte), step 2 = `fn_finished` avec `fn_random_ec_cert` (contenu aléatoire). OSSL rejette le Finished avec "unexpected message". LibreSSL traite le Finished malformé, émet le claim (avec toutes les clés à zéro), puis échoue aussi avec "sslv3 alert unexpected message".

**Classification probable :** BENIGN — LibreSSL émet le claim mais avec des clés nulles, ce qui signifie qu'aucune vraie session n'est établie. Les deux PUTs finissent par échouer. Pas de vulnérabilité exploitable.

**Trace représentative :** `./objective/20260428-221907105-2ed273f2e73bf0ea.trace`

---

## État de l'écriture des buckets

Au moment de l'interruption, **aucun bucket n'avait encore été écrit** dans
`./evaluation-ddyf/sort_objectives_ossl_libre.py` — le fichier ne contenait que le bucket
`no_errors/` initial.

L'analyse avait été complétée pour toutes les catégories ci-dessus. Les buckets suivants
étaient planifiés et prêts à être codés :

| Bucket prévu                            | Condition principale                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------------------|
| `tls12/`                                | `CheckAgentC(["protocol_config", "tls_version"], "V1_2")` catch-all                 |
| `ossl_client_ccs_unexpected/`           | `StatusC(OSSL, "ossl_statem_client_read_transition") + TermContainsC(OSSL, "fn_change_cipher_spec")` |
| `ossl_client_flight_unexpected/`        | `StatusC(OSSL, "ossl_statem_client_read_transition") + TermContainsC(OSSL, "fn_append_flight")` |
| `ossl_close_notify_unexpected/`         | `StatusC(OSSL, "ssl3_read_bytes") + TermContainsC(OSSL, "fn_alert_close_notify")`   |
| `ossl_renegotiation_disabled/`          | `StatusC(OSSL, "final_renegotiate") + TermContainsC(OSSL, "fn_server_hello")`       |
| `ossl_records_not_released_ccs/`        | `StatusC(OSSL, "tls_read_record:records not released") + TermContainsC(OSSL, "fn_alert_close_notify")` |
| `ossl_wrong_cipher_sh/`                 | `StatusC(OSSL, "set_client_ciphersuite:wrong cipher") + TermContainsC(OSSL, "fn_server_hello")` |
| `ossl_no_sigalg_binder/`               | `StatusC(OSSL, "tls_choose_sigalg") + TermContainsC(OSSL, "fn_fill_binder")`        |
| `libre_hello_request_first/`            | `StatusC(LIBRE, "CONNECT_CR_SRVR_HELLO") + TermContainsC(LIBRE, "fn_hello_request")` |
| `libre_empty_handshake_server/`         | `StatusC(LIBRE, "ACCEPT_SR_CLNT_HELLO") + TermContainsC(LIBRE, "fn_empty_handshake_message")` |
| `libre_protocol_version_ch/`            | `StatusC(LIBRE, "ACCEPT_SR_CLNT_HELLO") + TermContainsC(LIBRE, "fn_client_hello")`  |
| `libre_double_close_notify/`            | `StatusC(LIBRE, "ACCEPT_SR_FINISHED") + TermContainsC(LIBRE, "fn_alert_close_notify")` |
| Buckets BothAlert (×10–15 combinaisons) | `InnerKnowledgeC("Different(X, Y)") + TermContainsC(...)` pour chaque combinaison   |
| `libre_finished_claim_zeros/`           | `DifferentClaimC(in_first_type="()", in_second_type="Finished")`                     |

---

## Observations générales

- **OSSL est globalement plus strict** : il échoue plus tôt et plus souvent en premier (~55 % des cas de Status).
- **LibreSSL est plus permissif** : il continue là où OSSL s'arrête, mais finit souvent par échouer à son tour plus loin dans la trace.
- **Aucune vulnérabilité de sécurité claire n'a été trouvée** : les cas où un PUT "réussit" (Finished claim) alors que l'autre échoue impliquent des clés nulles ou des contextes manifestement invalides.
- **Le pattern le plus courant** (`InnerDiff IllegalParameter vs DecodeError`) est BENIGN : les deux rejectent le message, mais choisissent des alertes différentes.
- **Le cas le plus intéressant** reste `libre_double_close_notify` (catégorie 9) où OSSL exécute la trace complètement et LibreSSL échoue — OSSL est ici plus conforme à RFC 8446 §6.1.
