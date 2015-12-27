CC=gcc
CFLAGS=-Wall -Werror -g


all:
	#CHE SCHIFO DI Make FILE da fare BENE!
	make testServerClientBase
	
	make testServerClientRegister

	make testHanshake

testHanshake:
	mkdir -p test
	$(CC) $(CFLAGS) -o test/clientHandshakeTest HandshakeProtocol/clientHandshake.c HandshakeProtocol/ServerClientHandshakeProtocol.c HandshakeProtocol/ServerClientHello.c RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c
	$(CC) $(CFLAGS) -o test/serverHandshakeTest HandshakeProtocol/serverHandshake.c HandshakeProtocol/ServerClientHandshakeProtocol.c HandshakeProtocol/ServerClientHello.c RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c

testServerClientBase:
	#export LD_LIBRARY_PATH=./lib/
	#make test folder if doesn't exist
	mkdir -p test
	#make server (do better with a library)
	$(CC) $(CFLAGS) -o test/serverBasicTest BasicComunication/serverBasic.c HandshakeProtocol/ServerClientHandshakeProtocol.c HandshakeProtocol/ServerClientHello.c RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c
	#make client (do better with a library)
	$(CC) $(CFLAGS) -o test/clientBasicTest BasicComunication/clientBasic.c HandshakeProtocol/ServerClientHandshakeProtocol.c HandshakeProtocol/ServerClientHello.c RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c

testServerClientRegister:
	#make test folder if doesn't exist
	mkdir -p test
	#make server (do better with a library)
	$(CC) $(CFLAGS) -o test/serverRecordTest RecordProtocol/serverRecord.c  HandshakeProtocol/ServerClientHandshakeProtocol.c HandshakeProtocol/ServerClientHello.c RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c
	#make client (do better with a library)
	$(CC) $(CFLAGS) -o test/clientRecordTest RecordProtocol/clientRecord.c  HandshakeProtocol/ServerClientHandshakeProtocol.c HandshakeProtocol/ServerClientHello.c RecordProtocol/ServerClientRecordProtocol.c BasicComunication/ServerClientBasic.c