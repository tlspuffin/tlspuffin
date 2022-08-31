1. Perform an initial session TLS 1.3 session (which includes the first Client Hello)

2. Trigger a HelloRetryRequest after a resumed session

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


3. Send at least sqrt(300) + 1 identical ciphers in the second Client Hello

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


4. Repeat 3. for the third Client Hello

5. While accepting new messages from the client, the server accepts the third Client Hello


The reason for this is that the server is in the `SERVER_HELLO_RETRY_REQUEST_COMPLETE` state. That way it processes the third ClientHello with the call of `ProcessReply`.

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

6. The server processes the ciphers in the third Client Hello again in `RefineSuites`. The quadratic explosion makes the `suites` array overflow the stack.

Right now we only found a way to overflow with "existing" cipher suites (See 2.).
