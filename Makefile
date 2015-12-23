CC=gcc
CFLAGS=-Wall

testServerClientBase:
	#make test folder if doesn't exist
	mkdir -p test
	#make server
	$(CC) $(CFLAGS) -o test/testServer BasicComunication/testServer.c  BasicComunication/ServerClientBasic.c
	#make client
	$(CC) $(CFLAGS) -o test/testClient BasicComunication/testClient.c  BasicComunication/ServerClientBasic.c
