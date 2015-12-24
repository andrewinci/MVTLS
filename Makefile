CC=gcc
CFLAGS=-Wall

all:
	make testServerClientBase
	
	make testServerClientRegister

testServerClientBase:
	#make test folder if doesn't exist
	mkdir -p test
	#make server (do better with a library)
	$(CC) $(CFLAGS) -o test/serverBasicTest BasicComunication/serverBasic.c  BasicComunication/ServerClientBasic.c
	#make client (do better with a library)
	$(CC) $(CFLAGS) -o test/clientBasicTest BasicComunication/clientBasic.c  BasicComunication/ServerClientBasic.c

testServerClientRegister:
	#make test folder if doesn't exist
	mkdir -p test
	#make server (do better with a library)
	$(CC) $(CFLAGS) -o test/serverRecordTest RecordProtocol/serverRecord.c  RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c
	#make client (do better with a library)
	$(CC) $(CFLAGS) -o test/clientRecordTest RecordProtocol/clientRecord.c  RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c
