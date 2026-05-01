# BoringSSL NewSessionTicket Fix — Notes de session

## Objectif principal

Faire passer `test_seed_session_resumption_dhe::boringssl20260211`.

**Statut : ✅ RÉSOLU**

---

## Contexte technique

### Le problème de départ

`seed_session_resumption_dhe` accède à `(initial_server, 1)/MessageFlight` pour récupérer le
NewSessionTicket (NST) du serveur et le déchiffrer. Ce counter=1 correspond au 2ème vol de
messages non-vide émis par `initial_server`.

Structure de `seed_client_attacker` (la trace initiale) :
- **Step 0** : `InputAction(ClientHello)` → serveur répond (SH+EE+Cert+CV+Fin) → implicit read → **counter=0**
- **Step 1** : `InputAction(ClientFinished)` → serveur devrait envoyer NST → implicit read → **counter=1** (si non-vide)
- **Step 2** : `OutputAction` → explicit read

Le problème était que BoringSSL **n'émettait aucun NST**, donc `(initial_server, 1)/MessageFlight`
était vide, et la lecture/déchiffrement du ticket échouait.

---

## Causes racines identifiées (et résolues)

### Cause 1 : Extension `psk_key_exchange_modes` manquante dans le ClientHello

RFC 8446 § 4.2.9 : si un ClientHello ne contient pas `psk_key_exchange_modes`, le serveur NE DOIT PAS
envoyer de NewSessionTicket.

BoringSSL (dans `extensions.cc`, `ext_psk_key_exchange_modes_parse_clienthello`) :
```c
// We only support tickets with PSK_DHE_KE.
hs->accept_psk_mode = OPENSSL_memchr(CBS_data(&ke_modes), SSL_PSK_DHE_KE, ...) != nullptr;
```

Si `accept_psk_mode == false`, `add_new_session_tickets` retourne immédiatement sans rien émettre.

**Fix appliqué** (`tlspuffin/src/tls/seeds.rs`) : ajout de `fn_psk_exchange_mode_dhe_ke_extension`
dans le ClientHello de `seed_client_attacker` et `_seed_client_attacker_full`.

**Vérification** : `[INBOUND] found psk_key_exchange_modes ext (0x002d) at offset 216` — l'extension
est bien présente dans les octets livrés à BoringSSL.

### Cause 2 : BoringSSL diffère l'envoi des NST pour TCP

Malgré l'extension présente, les NSTs étaient générés (msg_callback se déclenchait avec
`msg_type=4` deux fois) mais `BIO_pending(agent->out) == 0` après `SSL_do_handshake`.

Raison dans `tls13_server.cc`, `do_send_new_session_ticket` (ligne 1473-1488) :
```c
// In TLS over TCP-like transports, we defer until the server performs a write.
// Consumers which don't write data to the client will need to do a zero-byte
// write if they wish to flush the tickets.
bool should_flush = sent_tickets && (SSL_is_dtls(ssl) || SSL_is_quic(ssl));
return should_flush ? ssl_hs_flush : ssl_hs_ok;
```

Pour TCP (notre cas avec BIO mémoire), BoringSSL **ne flush pas** les NSTs immédiatement.
Ils restent dans `pending_flight` jusqu'à ce que l'application appelle `SSL_write`.

**Fix appliqué** (`tlspuffin/harness/boringssl/src/put.c`, dans `boringssl_progress`) :
```c
if (ret == 1)
{
    // BoringSSL defers NST writes for TCP until the application writes.
    // A zero-byte SSL_write flushes the pending flight (NewSessionTickets).
    SSL_write(agent->ssl, "", 0);
}
```

---

## Fichiers modifiés

### `tlspuffin/harness/boringssl/src/put.c`

1. **`boringssl_create_server`** : ajout de `SSL_CTX_set_num_tickets(ssl_ctx, 2)` (redondant car
   la valeur par défaut est déjà 2 d'après `internal.h:3884`, mais explicite).

2. **`boringssl_progress`** : ajout du zero-byte `SSL_write` après `SSL_do_handshake` réussi,
   pour forcer le flush des NSTs différés.

### `tlspuffin/src/tls/seeds.rs`

1. **`seed_client_attacker`** : ajout de `fn_psk_exchange_mode_dhe_ke_extension` dans le
   ClientHello.

2. **`_seed_client_attacker_full`** : même ajout de `fn_psk_exchange_mode_dhe_ke_extension`.

---

## Approche abandonnée (snapshot BIO)

Une première tentative a consisté à snapshotter `BIO_pending()` dans le `msg_callback` au
moment de l'envoi du Finished serveur, puis à splitter `take_outbound` pour émuler deux vols
séparés. **Cette approche était fausse** car :

- Le `msg_callback` de BoringSSL se déclenche **AVANT** l'écriture dans le BIO
- `BIO_pending()` valait donc 0 au moment du callback (les octets sont écrits après)
- Résultat : `handshake_pending=0, splitting=true` → `take_outbound` retournait 0 immédiatement,
  jetant tous les messages → tous les tests BoringSSL échouaient

**Cette approche a été entièrement annulée (revert complet).**

---

## Résultats des tests

### État actuel (après les fixes NST)

| Test | Statut |
|------|--------|
| `test_seed_session_resumption_dhe::boringssl20260211` | ✅ ok |
| `test_seed_session_resumption_dhe_full::boringssl20260211` | ✅ ok |
| `test_seed_successful_with_tickets::boringssl20260211` | ✅ ok |
| `test_seed_client_attacker::boringssl20260211` | ✅ ok |
| `test_seed_successful::boringssl20260211` | ✅ ok |
| Tous les tests openssl340 | ✅ ok |
| `test_seed_session_resumption_ke::boringssl20260211` | ❌ FAILED (exclu des objectifs — voir ci-dessous) |
| `test_cipher_config_takes_effect::boringssl20260211` | ❌ FAILED (à corriger) |
| `test_cipher_config_takes_effect::wolfssl540` | ❌ FAILED (à corriger) |
| `test_cipher_config_takes_effect::openssl340` | ❌ FAILED (à corriger) |
| `test_differential_openssl340_vs_boringssl20260211` | ❌ FAILED (à corriger) |

---

## Problèmes restants et corrections proposées

### `test_seed_session_resumption_ke::boringssl20260211` — EXCLU

**Cause fondamentale** : BoringSSL ne supporte pas le mode `PSK_KE` (PSK sans DHE).

```c
// extensions.cc ligne 2248
// We only support tickets with PSK_DHE_KE.
hs->accept_psk_mode = OPENSSL_memchr(..., SSL_PSK_DHE_KE, ...) != nullptr;
```

**Symptôme** : `BAD_DECRYPT` — le serveur BoringSSL ignore le PSK (car mode non supporté),
fait une full handshake, mais le client envoie son Finished chiffré avec des clés PSK → mismatch.

**Solution proposée** : ajouter une capability (ex: `psk_ke_only_resumption`) dans le registre
PUT de BoringSSL et filtrer le test :
```rust
#[apply(test_puts, filter = all(tls13, tls13_session_resumption, psk_ke_only_resumption, not(disable_postauth)))]
```

---

### `test_cipher_config_takes_effect` (boringssl + wolfssl + openssl)

Trois causes distinctes :

#### BoringSSL (`signature_algorithm == 0`)

`boringssl_fill_claim()` dans `claims.cc` ne renseigne pas `claim->signature_algorithm`.
La valeur se trouve dans `hs->signature_algorithm`, mais `hs` est libéré avant l'appel à
`fill_claim`.

**Fix proposé** (3 fichiers) :
1. `claims.h` : ajouter `uint16_t signature_algorithm;` dans `SnappedTLS13Secrets`
2. `claims.cc` → `boringssl_snapshot_secrets()` : ajouter `secrets.signature_algorithm = hs->signature_algorithm;` (pendant que `hs` est encore vivant)
3. `claims.cc` → `boringssl_fill_claim()` : après la section cipher, lire la valeur snappée :
   ```c
   if (have_snapped && snapped.signature_algorithm != 0) {
       claim->signature_algorithm = (int)snapped.signature_algorithm;
   }
   ```
   `hs->signature_algorithm` est en TLS wire format (ex: `0x0804` pour rsa_pss_rsae_sha256),
   compatible avec les valeurs attendues par le test.

#### OpenSSL (`signature_algorithm == 0x0390` ≠ valeur TLS wire)

`ssl_lib.c:8088` utilise `lu->sig` qui est le NID EVP du type de clé (`EVP_PKEY_RSA_PSS = 912 = 0x390`), pas la valeur TLS wire.

```c
// Actuel (mauvais) :
claim->signature_algorithm = lu->sig;        // NID EVP, ex: 912
// Corrigé :
claim->signature_algorithm = (int)lu->sigalg; // TLS wire value, ex: 0x0804
```

**Fix proposé** (`vendor/openssl340/src/vendor/ssl/ssl_lib.c`) :
- Ligne 8088 : `lu->sig` → `(int)lu->sigalg`
- Ligne 8092 : `peer_lu->sig` → `(int)peer_lu->sigalg`

#### wolfSSL (`signature_algorithm == 0`)

wolfSSL 5.4 n'expose que `wolfSSL_get_signature_nid()` (qui renvoie un NID OpenSSL-compatible,
pas une valeur TLS wire). Le code correspondant dans le harness est commenté.

**Fix proposé** : deux options :
- **Option A** (plus simple) : ajouter une capability `reports_signature_algorithm` dans le
  registre PUT wolfSSL, et conditionner les assertions du test :
  ```rust
  if supports!(put, "reports_signature_algorithm") {
      assert!(finished.signature_algorithm != 0, ...);
      assert!(allowed_sigalgs.contains(&finished.signature_algorithm), ...);
  }
  ```
- **Option B** : accéder aux champs internes wolfSSL (`ssl->options.sigAlgo` + hash algo) pour
  reconstruire la valeur TLS wire — plus invasif.

---

### `test_differential_openssl340_vs_boringssl20260211`

Le test test_seed_session_resumption_ke ne passe pas et c'est normal. => A ignorer avec la capability

---

## Points clés à retenir

- Le `msg_callback` de BoringSSL se déclenche **avant** l'écriture dans le BIO (à l'inverse d'OpenSSL
  où il se déclenche après). Ne pas utiliser `BIO_pending()` dans le callback pour mesurer ce qui
  a été écrit.

- BoringSSL **diffère** le flush des NSTs pour TCP. Un `SSL_write(ssl, "", 0)` est nécessaire
  après la fin du handshake pour les forcer dans le BIO.

- BoringSSL ne supporte **que** `PSK_DHE_KE` (pas `PSK_KE`), à la fois comme client et comme
  serveur. C'est documenté dans le code source : _"We only support tickets with PSK_DHE_KE."_

- L'extension `psk_key_exchange_modes` (type `0x002d`, valeur `PSK_DHE_KE = 0x01`) **doit**
  être présente dans le ClientHello initial pour que BoringSSL émette des NSTs.

- BoringSSL envoie **toujours** les enregistrements CCS de compatibilité TLS 1.3 (serveur et
  client) — pas d'API publique pour les désactiver. OpenSSL les désactive explicitement via
  `SSL_OP_ENABLE_MIDDLEBOX_COMPAT`.

- Dans le patch OpenSSL (`ssl_lib.c`), `lu->sig` est le NID EVP du type de clé, **pas** la
  valeur TLS wire. Utiliser `lu->sigalg` pour avoir la valeur wire (ex: `0x0804`).

- Dans BoringSSL, `hs->signature_algorithm` contient la valeur TLS wire du sigalg choisi.
  Il faut la snapper depuis `boringssl_snapshot_secrets()` (pendant que `hs` est vivant)
  car `hs` est libéré après la fin du handshake.

- puffin injecte un `OutputAction` implicite après chaque `InputAction` (voir `trace.rs:1284`).
  Les NSTs de BoringSSL apparaissent donc dans la knowledge même sans `OutputAction` explicite,
  grâce au zero-byte `SSL_write` qui les flush dans le BIO pendant le traitement du ClientFinished.

---

## Comment lancer les tests

```bash
# Tous les tests seeds
cargo test -p tlspuffin --features=cputs --lib seeds

# Test spécifique
cargo test -p tlspuffin --features=cputs --lib tls::seeds::tests::test_seed_session_resumption_dhe_full

# Build + exécution
cargo build --features=cputs --bin tlspuffin
./target/debug/tlspuffin seed
./target/debug/tlspuffin execute seeds/tlspuffin::tls::seeds::seed_client_attacker.trace
```
