/*
 * sshpuffin/include/puffin/ssh_authorized_creds.h
 *
 * Shared server-side authorization policy for BOTH harnesses (libssh + wolfSSH),
 * defined once so the two stacks enforce an IDENTICAL boundary. Without a real
 * boundary a credential-confusion mutation has nothing to violate; with this
 * allow-list, a cross-vendor accept/reject asymmetry becomes a detectable
 * differential finding (no claims / security oracle needed).
 *
 * The three client identities live in the Rust mapper (fn_crypto.rs):
 *   A = user "user",  key A (== server host key), password "test"   -> AUTHORIZED
 *   B = user "userb", key B (RSA-3072),           password "testb"  -> AUTHORIZED
 *   C = user "userc", key C (RSA-3072),           password "testc"  -> NOT listed
 *
 * A publickey login is authorized iff (username, sha256(pubkey-blob)) is an
 * entry below. Both harnesses compute sha256 over the SAME on-the-wire public
 * key blob the client transmits (libssh ssh_get_publickey_hash / wolfSSH
 * wc_Sha256Hash), so the 32-byte fingerprints are identical across stacks and
 * equal ssh-keygen's SHA256 fingerprint. A password login is authorized iff
 * (username, password) matches. Everything else is rejected — including
 * identity C, and any cross-identity pairing (e.g. user "user" presenting key B).
 */
#ifndef PUFFIN_SSH_AUTHORIZED_CREDS_H
#define PUFFIN_SSH_AUTHORIZED_CREDS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    const char *user;
    uint8_t fp[32]; /* sha256 of the SSH public-key blob */
} SshAuthorizedKey;

typedef struct {
    const char *user;
    const char *password;
} SshAuthorizedPassword;

/* (username, sha256(pubkey-blob)) pairs granted publickey auth. */
static const SshAuthorizedKey SSH_AUTHORIZED_KEYS[] = {
    /* identity A — user "user", key A (== embedded server host key) */
    {"user",
     {0xa4, 0x9e, 0xba, 0xc7, 0x76, 0xcc, 0x3a, 0x80, 0x37, 0x2c, 0x44,
      0x2a, 0xc5, 0x4c, 0x2d, 0x7a, 0x9f, 0xd4, 0x5e, 0x7e, 0x93, 0xea,
      0x64, 0x81, 0xd1, 0xa5, 0x5a, 0x2c, 0x7e, 0x1b, 0x27, 0x29}},
    /* identity B — user "userb", key B (RSA-3072) */
    {"userb",
     {0x23, 0x8c, 0x19, 0xea, 0x25, 0xb8, 0xb9, 0xc1, 0xec, 0x15, 0xbc,
      0xd5, 0xf9, 0x10, 0xc0, 0x49, 0xc1, 0x3c, 0x52, 0x6b, 0x4d, 0x4b,
      0x64, 0x1c, 0xaf, 0xce, 0x63, 0x55, 0xc6, 0xb2, 0x3b, 0x0a}},
    /* identity C (user "userc", key C) is deliberately NOT authorized. */
};

/* (username, password) pairs granted password auth. */
static const SshAuthorizedPassword SSH_AUTHORIZED_PW[] = {
    {"user", "test"},
    {"userb", "testb"},
    /* identity C's password "testc" is deliberately NOT authorized. */
};

/* True iff (user, fp) is an authorized publickey pairing. */
static inline bool ssh_creds_key_authorized(const char *user, const uint8_t *fp,
                                            size_t fp_len) {
    if (user == NULL || fp == NULL || fp_len != 32)
        return false;
    for (size_t i = 0; i < sizeof(SSH_AUTHORIZED_KEYS) / sizeof(SSH_AUTHORIZED_KEYS[0]);
         i++) {
        if (strcmp(user, SSH_AUTHORIZED_KEYS[i].user) == 0 &&
            memcmp(fp, SSH_AUTHORIZED_KEYS[i].fp, 32) == 0)
            return true;
    }
    return false;
}

/* True iff (user, password) is an authorized password pairing. The password is
 * passed as a byte range (not necessarily NUL-terminated) to fit both APIs. */
static inline bool ssh_creds_password_authorized(const char *user,
                                                 const uint8_t *pw, size_t pw_len) {
    if (user == NULL || pw == NULL)
        return false;
    for (size_t i = 0; i < sizeof(SSH_AUTHORIZED_PW) / sizeof(SSH_AUTHORIZED_PW[0]);
         i++) {
        const char *want = SSH_AUTHORIZED_PW[i].password;
        size_t want_len = strlen(want);
        if (strcmp(user, SSH_AUTHORIZED_PW[i].user) == 0 && pw_len == want_len &&
            memcmp(pw, want, want_len) == 0)
            return true;
    }
    return false;
}

#endif /* PUFFIN_SSH_AUTHORIZED_CREDS_H */
