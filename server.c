#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL    -1
#define MAX_USER 1024

int bflag = 0;

SSL *userList[MAX_USER];
int userNum = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void *Servlet(void *data) /* Serve the connection -- threadable */
{
    SSL *ssl = (SSL *)data;

    char buf[1024] = {0};
    int sd, bytes;

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        while (1) 
        {  
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
            buf[bytes] = '\0';

            if ( bytes > 0 )
            {      
                printf("Client msg: \"%s\"\n", buf);

                if (bflag) {
                    pthread_mutex_lock(&mutex);
                    for (int i = 0; i < userNum; i++) {
                        SSL_write(userList[i], buf, bytes);
                    }
                    pthread_mutex_unlock(&mutex);
                }
                else {
                    SSL_write(ssl, buf, bytes);
                }
            }
            else
            {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */

    pthread_mutex_lock(&mutex);
    int t;
    for (t = 0; t < userNum; t++)
        if (userList[t] == ssl) break;

    for (int i = t; i < userNum - 1; i++)
        userList[i] = userList[i + 1];
    
    userNum--;
    pthread_mutex_unlock(&mutex);
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    int server;
    int portnum = atoi(argv[1]);
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    if (argc < 2) {
		printf("syntax : ssl_server <port> [-b]\n");
		printf("sample : ssl_server 1234 -b\n");
		return -1;
	}

    int c;
	while ((c = getopt(argc, argv, "b")) != -1) {
		switch (c) {
			case 'b':
				bflag = 1;
				break;
		}
	}

    pthread_t t;

    // Initialize the SSL library
    SSL_library_init();
    
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(portnum);    /* create server socket */

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        
        pthread_mutex_lock(&mutex);
        userList[userNum++] = ssl;
        pthread_mutex_unlock(&mutex);

        pthread_create(&t, NULL, Servlet, ssl);
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
