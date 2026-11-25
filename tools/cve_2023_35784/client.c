/*
 * Minimal LibreSSL TLS client for CVE-2023-35784 (double free / use-after-free after SSL_clear).
 *
 * Connects, completes the handshake (certificate verification disabled, but the library still
 * builds and stores `verified_chain`), then calls SSL_clear() like a connection-pooling
 * application reusing its SSL object would.
 *
 * Usage: client <host> <port> [--no-clear] [--reconnect] [--set-connect-state]
 *
 *   --no-clear           skip SSL_clear() (control)
 *   --reconnect          after SSL_clear(), open a new socket and handshake again on the same SSL
 *   --do-handshake      drive handshakes with SSL_do_handshake() (as the tlspuffin harness does)
 *                       instead of SSL_connect()
 *   --set-connect-state  call SSL_set_connect_state() again after SSL_clear()
 *
 * LibreSSL note: SSL_connect() dispatches on `s->method->ssl_connect`, SSL_do_handshake() on
 * `s->internal->handshake_func`. A TLS 1.2 handshake leaves handshake_func = ssl3_connect and
 * SSL_clear() does not reset it, so a second SSL_do_handshake() skips tls13_legacy_connect and
 * fails with "internal error" unless SSL_set_connect_state() is called again.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static int connect_to(const char *host, const char *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(port))};
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("connect");
        exit(2);
    }
    return fd;
}

static int use_do_handshake;

static int handshake(SSL *ssl, int fd, const char *what)
{
    SSL_set_fd(ssl, fd);
    if ((use_do_handshake ? SSL_do_handshake(ssl) : SSL_connect(ssl)) != 1)
    {
        fprintf(stderr, "[client] %s: handshake failed\n", what);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    printf("[client] %s: handshake done: %s %s, verified_chain set: %s\n", what, SSL_get_version(ssl),
           SSL_get_cipher(ssl), SSL_get0_verified_chain(ssl) ? "yes" : "no");
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <host> <port> [--no-clear] [--reconnect] [--set-connect-state] [--do-handshake]\n", argv[0]);
        return 2;
    }
    int do_clear = 1, reconnect = 0, set_state = 0;
    for (int i = 3; i < argc; i++)
    {
        do_clear &= strcmp(argv[i], "--no-clear") != 0;
        reconnect |= strcmp(argv[i], "--reconnect") == 0;
        set_state |= strcmp(argv[i], "--set-connect-state") == 0;
        use_do_handshake |= strcmp(argv[i], "--do-handshake") == 0;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL *ssl = SSL_new(ctx);
    SSL_set_connect_state(ssl);

    int fd = connect_to(argv[1], argv[2]);
    if (!handshake(ssl, fd, "first"))
        return 3;

    int rc = 0;
    if (do_clear)
    {
        printf("[client] calling SSL_clear()\n");
        fflush(stdout);
        printf("[client] SSL_clear() = %d\n", SSL_clear(ssl));
        close(fd);
        if (set_state)
            SSL_set_connect_state(ssl);
        if (reconnect)
        {
            fd = connect_to(argv[1], argv[2]);
            if (!handshake(ssl, fd, "second"))
                rc = 4;
        }
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("[client] done, no crash (rc=%d)\n", rc);
    return rc;
}
