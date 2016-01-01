CC := gcc # This is the main compiler
#CC := clang --analyze # and comment out the linker last line for sanity
SRCDIR := src
BUILDDIR := build
CFLAGS := -g -Wall -std=gnu99 -O0 -D MAKEFILE 
OPENSSLFLAGS :=-I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
LFLAGS := -pthread
INC :=  -I include
GREEN=\033[0;32m
RED=\033[0;31m
NC=\033[0m # No Color

clientServer: handshakeProtocol
	@mkdir -p bin/
	@printf "${GREEN}** Make server **${NC}\n"
	$(CC) $(CFLAGS) $(SRCDIR)/SSLServer.c $(INC) -o bin/SSLServer $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS)  $(OPENSSLFLAGS)
	@printf "${GREEN}** Make client **${NC}\n"
	$(CC) $(CFLAGS) $(SRCDIR)/SSLClient.c $(INC) -o bin/SSLClient $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS)  $(OPENSSLFLAGS)


allTest: testBasic testRecord testHandshake

# Tests
testHandshake: TEST_NAME=Handshake
testHandshake: handshakeProtocol
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME) $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS)  $(OPENSSLFLAGS)
	$(CC) $(CFLAGS) tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME) $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS) $(OPENSSLFLAGS)

testRecord: TEST_NAME=Record
testRecord: recordProtocol
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME) $(BUILDDIR)/ServerClientBasic.o $(BUILDDIR)/ServerClientRecordProtocol.o $(LFLAGS)
	$(CC) $(CFLAGS) tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME) $(BUILDDIR)/ServerClientBasic.o $(BUILDDIR)/ServerClientRecordProtocol.o $(LFLAGS)

testBasic: TEST_NAME=Basic
testBasic: basicProtocol
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME) $(BUILDDIR)/ServerClientBasic.o -pthread
	$(CC) $(CFLAGS) tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME) $(BUILDDIR)/ServerClientBasic.o -pthread

handshakeProtocol: recordProtocol handshakeMessages
	@printf "${GREEN}** Make object code for handshake protocol**${NC}\n"
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/ServerClientHandshakeProtocol.o $(SRCDIR)/ServerClientHandshakeProtocol.c

handshakeMessages:
	@printf "${GREEN}** Make object code for handshake messages**${NC}\n"
	@mkdir -p $(BUILDDIR)/HandshakeMessages
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/HandshakeMessages/Certificate.o $(SRCDIR)/HandshakeMessages/Certificate.c
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/HandshakeMessages/ServerClientHello.o $(SRCDIR)/HandshakeMessages/ServerClientHello.c

recordProtocol: basicProtocol
	@printf "${GREEN}** Make object code for record protocol**${NC}\n"
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/ServerClientRecordProtocol.o $(SRCDIR)/ServerClientRecordProtocol.c

basicProtocol:
	@printf "${GREEN}** Make object code for basic protocol**${NC}\n"
	@mkdir -p $(BUILDDIR)/
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/ServerClientBasic.o $(SRCDIR)/ServerClientBasic.c

clean:
	@printf "${RED}** Clean **${NC}\n"
	@echo " $(RM) -r $(BUILDDIR) $(TARGET)"; $(RM) -r $(BUILDDIR) $(TARGET)
	@echo " $(RM) -r bin"; $(RM) -r bin
