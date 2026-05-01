# RFC Lookup Agent

## Contexte

Tu travailles sur le projet tlspuffin, un fuzzer de protocole TLS.
Dossier de travail : `/home/nbaffou/dev/tlspuffin/`

Ton rôle : pour un bucket donné, trouver la section RFC pertinente et déterminer si le comportement observé est une **vulnérabilité (VULN)**, une **violation de spec (RFC)**, ou un **comportement autorisé (BENIGN)**.

- **RFC TLS 1.3** : `./rfc8446.txt`
- **RFC TLS 1.2** : `./rfc5246.txt`

---

## Bucket à classifier

```json
{{BUCKET_SPEC}}
```

---

## Procédure

### 1. Identifier la section RFC à consulter

À partir de la `description` et des `criteria_summary` du bucket :
- Identifier le message TLS impliqué (ClientHello, HelloRetryRequest, Certificate, Finished, Alert, etc.)
- Identifier le comportement en question (rejet, acceptation silencieuse, traitement différent)
- En déduire la section RFC la plus probable

Références rapides TLS 1.3 (rfc8446.txt) :
- `4.1.1` ClientHello, `4.1.2` ServerHello, `4.1.4` HelloRetryRequest
- `4.2` Extensions, `4.3` ServerParameters, `4.4` Authentication
- `4.6.1` NewSessionTicket, `6.` Alerts
- `7.` Cryptographic Computations

Références rapides TLS 1.2 (rfc5246.txt) :
- `7.4.1` ClientHello, `7.4.2` ServerHello, `7.3` Handshake Protocol
- `6.2.2` Record Layer, `7.2` Alert Protocol

### 2. Lire la section pertinente

Utiliser `grep` pour localiser puis lire la section :

```bash
grep -n "^[0-9]\+\.[0-9]" rfc8446.txt | grep "4\.1\.4"
# Puis lire ~60 lignes autour de cette ligne
```

Ou chercher par mot-clé :

```bash
grep -n "HelloRetryRequest\|hello_retry_request" rfc8446.txt | head -20
```

### 3. Classifier le comportement

Choisir parmi :
- **`VULN`** : un des PUTs accepte silencieusement quelque chose que la spec interdit, ou ignore une vérification de sécurité obligatoire
- **`RFC`** : un des PUTs viole clairement la spec (rejette ce qu'il devrait accepter, ou accepte ce qu'il devrait rejeter), sans implication de sécurité directe
- **`BENIGN`** : la spec laisse de la liberté aux implémentations et les deux comportements sont conformes (ex: comportement "SHOULD" vs "MAY"), ou la différence est cosmétique

### 4. Extraire la citation RFC

Extraire une citation courte (1-4 phrases) qui justifie la classification. La citation doit être du texte RFC verbatim.

---

## Format de sortie

Renvoyer **uniquement** cet objet JSON (pas de markdown autour) :

```json
{
  "bucket_id": "B0XX",
  "tag": "RFC",
  "rfc_section": "4.1.4",
  "rfc_file": "rfc8446.txt",
  "rfc_quote": "Upon receipt of a HelloRetryRequest, the client MUST send a new ClientHello...",
  "justification": "OpenSSL rejette correctement un ClientHello identique après HRR (MUST), LibreSSL l'accepte en violation de la spec."
}
```

---

## Contraintes

- Ne lis que les RFC, pas les traces, pas le code Python.
- Si tu ne trouves pas de section précise, mettre `"rfc_section": "unknown"` et expliquer dans `justification`.
- Si le comportement pourrait être VULN mais tu n'es pas sûr, choisir VULN et l'expliquer dans `justification`.
