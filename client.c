#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1

void *do_send(void *);
void *do_recv(void *);

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
SSL_CTX* InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *hostname, *portnum;

    if (count != 3) {
		printf("syntax : ssl_client <host> <port>\n");
		printf("sample : ssl_client 127.0.0.1 1234\n");
		return -1;
	}

    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        pthread_t pid[2];
        int thr_id, status;

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */

        thr_id = pthread_create(&pid[0], NULL, do_send, ssl);
        thr_id = pthread_create(&pid[1], NULL, do_recv, ssl);

        pthread_join(pid[0], (void **)&status);
        pthread_join(pid[1], (void **)&status);

        SSL_free(ssl);
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}

void *do_send(void *data)
{
    SSL *ssl = (SSL *)data;

    while (1)
    {
        char buf[BUFSIZ];

        scanf("%s", buf);

        SSL_write(ssl, buf, strlen(buf));
    }
}

void *do_recv(void *data)
{
    SSL *ssl = (SSL *)data;

    while (1)
    {
        char buf[BUFSIZ];

        ssize_t bytes = SSL_read(ssl, buf, BUFSIZ);
        buf[bytes] = 0;
        printf("%s\n", buf);

    }
}