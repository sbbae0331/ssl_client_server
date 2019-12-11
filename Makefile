all: ssl_client ssl_server

ssl_client: client.c
	gcc -Wall -o ssl_client client.c -L/usr/lib -lssl -lcrypto -lpthread

ssl_server: server.c
	gcc -Wall -o ssl_server server.c -L/usr/lib -lssl -lcrypto -lpthread

clean:
	rm -f ssl_client ssl_server

