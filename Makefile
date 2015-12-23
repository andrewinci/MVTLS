CC=gcc
CFLAGS=-Wall

testSocket:
	#make server
	$(CC) $(CFLAGS) -o testServer testServer.c  ServerClientFileSocket/ServerClientFileSocket.c
	#make client
	$(CC) $(CFLAGS) -o testClient testClient.c  ServerClientFileSocket/ServerClientFileSocket.c
