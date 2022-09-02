***** THE ISSUES ARE EMBARGOED UNTIL 0700 CEST 2022/09/23 *****
***** DO NOT PUBLICLY DISCLOSE THE ISSUES UNTIL THE EMBARGO DATE *****

Hello wolfSSL Team,

After we discovered and disclosed two vulnerabilities (CVE-2022-38152,  CVE-2022-38153) we just discovered another issue (CVE-2022-39173) the day after the previous embargo ended. This issue was again discovered automatically using the tlspuffin fuzzer. See below the SUMMARY and DETAILS about the discovered issue.

Inria and Trail of Bits are informing you as a community service, and so we do not seek a bug bounty on these issues.

We will be publicly disclosing the CVEs on 2022/09/23 (23rd of September, 2022) at 0700 CEST.

As we continue to develop tlspuffin, other bugs might be found this way. We will soon make a public, stable release of tlspuffin, which could be used as a CI-based fuzzer for your project should you find it useful.

Kind regards,
Tlspuffin Team
- Max Amman (work done when at Inria, LORIA and later when at Trail of Bits)
- Lucca Hirschi (Inria, LORIA)
- Steve Kremer (Inria, LORIA)
  This vulnerability has been found in the context of a research project on Cryptographic Protocol Logic Fuzz Testing whose tlspuffin is a proof of concept.


# SUMMARY

In wolfSSL 5.4.0 and 5.5.0 (and possibly earlier versions) malicious clients can cause a buffer-overflow during a resumed TLS 1.3 handshake. If an attacker resumes a previous TLS session by sending a maliciously crafted Client Hello, followed by another maliciously crafted Client Hello. In total 3 Client Hellos have to be sent. One in the initial session, another one in the resumed session and a third one as a response to a Hello Retry Request message.

The malicious Client Hellos contains a list of supported cipher suites, which contain at least `⌊sqrt(150)⌋ + 1 = 13` duplicates and less than 150 ciphers in total. The buffer-overflow occurs in the `RefineSuites` function. An overflow of 44700 bytes is possible and has been confirmed: this covers at least the stack frame of `refineSuites` and a large portion of the caller (`CheckPreSharedKeys`), hence including the return address of the former.

We confirmed the vulnerability by sending packets over TCP to a Wolfssl server, freshly built from the sources at https://github.com/wolfSSL/wolfssl/tags with the `--enable-all` flag (even though only flags enabling TLS1.3, PSK, and resumptiom might suffice). We can provide sources for our software (tlspuffin) that produce those packets.

It is very likely that there is a way to craft an exploit which can cause a RCE. We have not yet created such an exploit as it would likely depend on the memory layout of the binary which uses wolfSSL.

Moreover, the size of the overflow can be fine-tuned in order not to smash the stack and continue the execution with a too large length of suites buffer and that will cause other routines that iterate over this buffer (e.g., `FindSuiteSSL`) to misbehave. Hypothetically, this might be exploited to make the server use a cipher it should not accept such as `nullcipher` that would open up new downgrade attack vectors.
While this remains hypothetical, the buffer overflow itself has been confirmed.


# DETAILS

Line numbers below are valid for the wolfSSL Git tag [v5.4.0-stable](https://github.com/wolfSSL/wolfssl/tree/v5.4.0-stable).

The bug exists in the RefineSuites function. In the following we want to explain why the function is able to overflow the `suites` array.

```c
/* Refine list of supported cipher suites to those common to server and client.
 *
 * ssl         SSL/TLS object.
 * peerSuites  The peer's advertised list of supported cipher suites.
 */
static void RefineSuites(WOLFSSL* ssl, Suites* peerSuites)
{
byte   suites[WOLFSSL_MAX_SUITE_SZ];
word16 suiteSz = 0;
word16 i, j;

XMEMSET(suites, 0, WOLFSSL_MAX_SUITE_SZ);

for (i = 0; i < ssl->suites->suiteSz; i += 2) {
for (j = 0; j < peerSuites->suiteSz; j += 2) {
if (ssl->suites->suites[i+0] == peerSuites->suites[j+0] &&
ssl->suites->suites[i+1] == peerSuites->suites[j+1]) {
suites[suiteSz++] = peerSuites->suites[j+0];
suites[suiteSz++] = peerSuites->suites[j+1];
}
}
}

ssl->suites->suiteSz = suiteSz;
XMEMCPY(ssl->suites->suites, &suites, sizeof(suites));
}
```

The `RefineSuites` function expects a `WOLFSSL` struct which contains a list of acceptable ciphers suites (`ssl->suites->suites`), as well as an array of peer cipher suites (`peerSuites`). Both inputs are bounded by WOLFSSL_MAX_SUITE_SZ, which is equal to 300 bytes or 150 cipher suites.

Let us assume that `ssl->suites` consists of a single cipher suite like `TLS_AES_256_GCM_SHA384` and the `peerSuites` list contains the same cipher thirteen times. The `RefineSuites` function will iterate for each element in `ssl->suites` over `peerSuites` and append the suite to `suites` if it is a match. The `suites` array has a maximum length of `WOLFSSL_MAX_SUITE_SZ == 300 bytes == 150 suites`.

With the just mentioned example input, the length of `suites` will now equal thirteen. The `suites` array is now copied to the `WOLFSSL` struct in the last line of the listing above. Therefore, `ssl->suites` contains now thirteen times the `TLS_AES_256_GCM_SHA384` cipher suite.

Let us now call the same `RefineSuites` function again on the modified `WOLFSSL` struct and the same `peerSuites` list. The `RefineSuites` function will iterate for each element in `ssl->suites` over `peerSuites` and append the suite to `suites` if it is a match. Because `ssl->suites` contains already 13 times the `TLS_AES_256_GCM_SHA384` cipher suite, in total 13 x 13 = 169 cipher suites are written to `suites`. 169 cipher suites require 338 bytes, which is more than what's available on the stack. The buffer overflows.

The maximum size of `peerSuites` is 150 cipher suites. Therefore, an overflow of 44700 bytes is possible and has been confirmed.

The buffer `ssl->suites->suites` is supposed to be reset to only contain the acceptable ciphers at each session start. However, by provoking a `HELLO CLIENT RETRY REQUEST`, it is possible to make `refineSuites` called twice as explained next.


## TRIGGERING THE BUFFER OVERFLOW

In order to cause the above buffer-overflow, it is required to call `RefineSuites` twice. Malicious clients need to perform the handshake in a certain way to reach this situation.
The buffer overflow at the attacked server can be obtained at least in the following situation:

1. Sending an initial genuine Client Hello (`CH1`) to the server and then completing a full handshake, thus establishing a PSK.

2. Resume the previous session by sending a second Client Hello (`CH2`) with the following criteria:
   - Exclude the `support_group_extension`, to cause a Hello Retry Request
   - Include a binder which cryptographically binds this session to the previous one.
   - Include a list of cipher suites that contains a repetition of `n` times the same cipher `c` with `13 <= n < 150`, deemed acceptable by the server.

   The server will parse this message, enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and stores at least `n` times the cipher `c` in `ssl->suites->suites` by calling `RefineSuites`.

3. Sending a third Client Hello (`CH3`) with the same criteria as in step 2.
   The server will parse this message and because `ssl->suites->suites` already contains `n` times the cipher `c`, `RefineSuites` will write in `suites` at least until `suites[n*2]` which overflows since `n*2 > 300`.


### STEP 2. DETAILS

During step 2., we want to cause the server to perform a Hello Retry Request.

This is possible by not sending a supported group in the CH2. By not sending a support group extension, the function `TLSX_SupportedGroups_Find` will return false.

```c
static int TLSX_SupportedGroups_Find(WOLFSSL* ssl, word16 name)
{
    ...
        /* Check consistency now - extensions in any order. */
        if (!TLSX_SupportedGroups_Find(ssl, clientKSE->group))
            continue;
    ...
```

This will cause clientKSE to be `NULL` and `doHelloRetry` will be set to 1.

```c
int TLSX_KeyShare_Establish(WOLFSSL *ssl, int* doHelloRetry)
{
    ...
    /* No supported group found - send HelloRetryRequest. */
    if (clientKSE == NULL) {
        /* Set KEY_SHARE_ERROR to indicate HelloRetryRequest required. */
        *doHelloRetry = 1;
        return TLSX_KeyShare_SetSupported(ssl);
    }
    ...
```

Finally, the server enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` in the function `VerifyServerSuite` while verifying the server suite when processing CH2.

```c
    /* Make sure server cert/key are valid for this suite, true on success
     * Returns 1 for valid server suite or 0 if not found
     * For asynchronous this can return WC_PENDING_E
     */
static int VerifyServerSuite(WOLFSSL* ssl, word16 idx)
{
...
if (IsAtLeastTLSv1_3(ssl->version) &&
ssl->options.side == WOLFSSL_SERVER_END) {
int doHelloRetry = 0;
/* Try to establish a key share. */
int ret = TLSX_KeyShare_Establish(ssl, &doHelloRetry);
if (doHelloRetry) {
ssl->options.serverState = SERVER_HELLO_RETRY_REQUEST_COMPLETE;
}

...
}
...
```


### STEP 3. DETAILS

The server is now in a state in which it expects another Client Hello (`CH3`) from the client.

The server is now in the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and will process the third ClientHello (`CH3`) with the call of `ProcessReply` before reaching the `TLS13_ACCEPT_SECOND_REPLY_DONE` state.

```c
int wolfSSL_accept_TLSv13(WOLFSSL* ssl)
{
    ...
        case TLS13_ACCEPT_FIRST_REPLY_DONE :
            if (ssl->options.serverState ==
                                          SERVER_HELLO_RETRY_REQUEST_COMPLETE) {
                ssl->options.clientState = CLIENT_HELLO_RETRY;
                while (ssl->options.clientState < CLIENT_HELLO_COMPLETE) {
                    if ((ssl->error = ProcessReply(ssl)) < 0) {
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                }
            }

            ssl->options.acceptState = TLS13_ACCEPT_SECOND_REPLY_DONE;
            WOLFSSL_MSG("accept state ACCEPT_SECOND_REPLY_DONE");
            FALL_THROUGH;
    ...
```

Note that the length of the list of ciphers in `CH3` does not necessarily have to be the same as the one of `CH2` and can be adjusted to fine-tune the size of the overflow.

Note also that, on the contrary to `CH2`, `CH3` does not necessarily have to put the server in the `SERVER_HELLO_RETRY_REQUEST_COMPLETE` state and can thus contain a supported group, which could be included to possibly make the server continue the processing of `CH3`.

# EXPLOITATION

In wolfSSL 5.4.0, using the standard build options, only the following bytes can be used to overflow the `suites` array. They are the default cipher suites which are accepted by the server.

```
13 01 13 02 13 03 00 33 00 39 00 ab 00 aa 00 b3 00 b2 c0 13 c0 14 c0 09 c0 0a 00 67 00 6b 00 9e 00 9f c0 2f c0 30 c0 2b c0 2c c0 27 c0 23 c0 28 c0 24 cc a8 cc a9 cc aa cc 13 cc 14 cc 15 c0 37 d0 01 cc ab cc ac cc ad
```

We suspect that it is possible to craft an exploit which could lead to RCE if any of the above bytes coincides with the memory address of executable code. Depending on the memory layout of the binary it could be possible to gain RCE.
More bytes could be used to overflow `suites` if more ciphers were configured to be accepted with the server, e.g., with options like `--enable-blake2`.

We confirmed that this could also be exploited to smash the stack and cause the server to crash with a SEG FAULT by using large list of ciphers.

Finally, by fine-tuning the length of the overflow and by including the supported group in `CH3`, it could be possible to make the server process `CH3` with a `ssl->suites->suites->suiteSz` value that exceeds 300. This way, routines like `FindSuiteSSL` that will iterate over `ssl->suites->suites` (allocated on 300 bytes) until `ssl->suites->suiteSz` (>300) will also iterate over bytes that contain other fields such as `ssl->suites->hashSigAlgo` or even over attacker-controlled fields such as `ssl->clientSecret`. It is likely that this could be exploited to make such routines return arbitrary values. For example, it might be exploited to make the server use a cipher it should not accept such as `nullcipher`. This way, a MITM attacker might be able to downgrade TLS 1.3 sessions by forcing clients and servers to use weak suites that should not be accepted.

# FURTHER CONCERNS

We observed that the server is accepting the `CH2` Client Hello message and issues a Hello Retry Request, even though `CH2` does not contain supported groups. Clients are not allowed to add the supported groups extension in the retry Client Hello (`CH3`) according to the RFC 8446 in section [4.1.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2). The addition of supported groups is not allowed when retrying the Client Hello.
We suggest to abort the handshake when receiving `CH2` instead of offering the client a retry.

TODO: discuss the feasibility of ddos ? keeping a ssl session open forever by looping in hello retries ?