# SUMMARY

 - buffer overflow
 - rewrite part of ssl struct at the server
 - make ssl->suites->suiteSz larger than it should 
 - ??

## Potential impact
TODO

# STEPS TO REPRODUCE

The buffer overflow at the attacked server is obtained by:
 1. sending a first genuine, standard client hello (`CH1`) to the server and then completes a full handshake, thus establishing a Pre-Shared Key (PSK).
 2. sending a second client hello (`CH2`) with the following specification:
    - remove the `support_group_extension`
    - includes a PSK associated to the session established at step 1
    - includes a list of ciphers that contains at least a repetition of `n` times the same cipher `c`, accepted by the server
 
    The server will parse this message and enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and store in `ssl->suites->suites` at least `n` times the cipher `c`.
 3. sending a third client hello (`CH3`) with the following specification:
    - includes a PSK associated to the session established at step 1
    - includes a list of ciphers that contains at least a repetition of `n` times the same cipher `c`, accepted by the server 
   
    The server will parse this message and because `ssl->suites->suites` already contains `n` times the cipher `c`, the flawed logic of the function `refineSuites` will provoke a buffer overflow.

## DETAILS

1. Perform an initial TLS 1.3 session with a full handshake (which includes the first Client Hello `CH1`). Note that the ssl context of that session can be cleared at this point without impacting the following.

2. Trigger with a second client hello (`CH2`) a HelloRetryRequest after a PSK-based resumed session.

We want to make sure that `doHelloRetry` is true during the second Client Hello to enter state `SERVER_HELLO_RETRY_REQUEST_COMPLETE`. In the initial session it was false.
We can make it true by not sending supported groups in the second Client Hello.

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

`TLSX_SupportedGroups_Find` is false if the `TLSX_SUPPORTED_GROUPS` extension is not sent in the second Client Hello.

```c
        /* Check consistency now - extensions in any order. */
        if (!TLSX_SupportedGroups_Find(ssl, clientKSE->group))
            continue;
```

```c
    /* No supported group found - send HelloRetryRequest. */
    if (clientKSE == NULL) {
        /* Set KEY_SHARE_ERROR to indicate HelloRetryRequest required. */
        *doHelloRetry = 1;
        return TLSX_KeyShare_SetSupported(ssl);
    }
```


In `CH2`, we also send at least 13 identical ciphers.

NOTE: Only ciphers which are supported by the server are allowed! The following bytes represent accepted values by wolfSSL 5.4.0:

13 01
13 02
13 03
00 33
00 39
00 ab
00 aa
00 b3
00 b2
c0 13
c0 14
c0 09
c0 0a
00 67
00 6b
00 9e
00 9f
c0 2f
c0 30
c0 2b
c0 2c
c0 27
c0 23
c0 28
c0 24
cc a8
cc a9
cc aa
cc 13
cc 14
cc 15
c0 37
d0 01
cc ab
cc ac
cc ad


Ciphers fromt the second Client Hello are processed in this function:

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
As a result, `ssl->suites->suites` will at least contain 13 times the ciphers that was included 13 times in `CH2`.

3. Repeat step 2 for the third Client Hello `CH3` (we can choose `CH3:=CH2`, one can also includes support_group_extension in `CH3`. The server will parse `CH3` because it is still in the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE`. That way it processes the third ClientHello with the call of `ProcessReply`. 
```c
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
```

  And yet, `ssl->suites->suites` has been filled up with all the ciphers from the list we sent at step 2. Even though the client hello from step 2 did not yield a full, valid handshake, the side effect of modifying ssl->suites->suites remains.
  The ciphers from `CH3` are processed again in `RefineSuites`. But now, `ssl->suites->suites` already contains 13 times the cipher that is repeated in `CH3`. The quadratic explosion due to the flawed logic of `RefineSuites` makes the `suites` array overflow the stack.

Right now we only found a way to overflow with "existing" cipher suites (See 2.).

## NUMBER OF CIPHERS ADJUSTING THE OVERFLOW
The list of ciphers in the two client hello retry can be as large as 149 repeated ciphers (a larger list is rejected by the server). In that case, we were able to reach `suitesSz = 29461` so an overflow of 29161 bytes. With only 15 equal ciphers in the list, we reach `suiteSz = 450` so an overflow of 150 bytes. There is an overflow starting with 13 equal ciphers in the list, but no overflow was found with 12 equal ciphers in the list.

# AFFECTED VERSIONS
TODO

# SUGGESTED REMEDIATION
We recommend the following fixes.

## A: Fixing the logic of refineSuite
Either:
 1. Reset `ssl->suites->suites` with `ìnternal.c::int InitSSL_Suites(WOLFSSL* ssl)` at the beginning of RefineSuites if a specific flag ssl->suites->clean is set to 0. refineSuites sets it to 1. ìnternal.c::int InitSSL_Suites(WOLFSSL* ssl) sets it to 0.
 2. Reset `ssl->suites->suites` with `ìnternal.c::int InitSSL_Suites(WOLFSSL* ssl)` at the beginning of RefineSuites.
 3. Add bound checks in refineSuites. Conditional becomes:
```c
   (suiteSz < WOLFSSL_MAX_SUITE_SZ &&
    ssl->suites->suites[i+0] == peerSuites->suites[j+0] &&
    ssl->suites->suites[i+1] == peerSuites->suites[j+1])
```

## B: Fixing the HELLO_RETRY state machine
TODO ??

## C: OTHER STUFF?

# Authors  [TO DISCUSS]
Max Amman (part of the work was done when M. Amman was at Inria and some other part when M. Amman was at Trail of Bits)
Lucca Hirschi (Inria)
This vulnerability has been found in the context of a research project on Cryptographic Protocol Logic Fuzz Testing whose tlspuffin is a proof of concept.