CC := gcc # This is the main compiler
#CC := clang --analyze # and comment out the linker last line for sanity
SRCDIR := src
BUILDDIR := build
CFLAGS := -g -Wall -std=gnu99 -D MAKEFILE 
OPENSSLINCLUDE ?= -I/usr/local/ssl/include -L/usr/local/ssl/lib
OPENSSLFLAGS := -lssl -lcrypto -ldl
OPENSSL := $(OPENSSLFLAGS) $(OPENSSLINCLUDE)
LFLAGS := -pthread
INC :=  -I include $(OPENSSL)
GREEN=\033[0;32m
RED=\033[0;31m
NC=\033[0m # No Color

# Final objects

clientServer: TLS
	@mkdir -p bin/
	@printf "${GREEN}** Make server **${NC}\n"
	$(CC) $(CFLAGS) $(SRCDIR)/Target/server.c $(INC) -o bin/TLSServer $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS)  $(OPENSSL)
	@printf "${GREEN}** Make client **${NC}\n"
	$(CC) $(CFLAGS) $(SRCDIR)/Target/client.c $(INC) -o bin/TLSClient $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS)  $(OPENSSL)

# Tests

tests: testCertificate testBasic testRecord testHandshake

testCertificate:
	$(CC) $(CFLAGS) tests/testCertificate.c $(INC) -o bin/testCertificate $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS) $(OPENSSL)


testHandshake: TEST_NAME=Handshake
testHandshake: handshakeProtocol
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME) $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS)  $(OPENSSL)
	$(CC) $(CFLAGS) tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME) $(shell find $(BUILDDIR) -name '*.o') $(LFLAGS) $(OPENSSL)

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

# Protocols
TLS: handshakeProtocol
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/Crypto.o $(SRCDIR)/Crypto.c
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/TLS.o $(SRCDIR)/TLS.c

handshakeProtocol: recordProtocol handshakeMessages
	@printf "${GREEN}** Make object code for handshake protocol**${NC}\n"
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/ServerClientHandshakeProtocol.o $(SRCDIR)/ServerClientHandshakeProtocol.c

handshakeMessages:
	@printf "${GREEN}** Make object code for handshake messages**${NC}\n"
	@mkdir -p $(BUILDDIR)/HandshakeMessages
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/HandshakeMessages/Certificate.o $(SRCDIR)/HandshakeMessages/Certificate.c
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/HandshakeMessages/ServerClientHello.o $(SRCDIR)/HandshakeMessages/ServerClientHello.c
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/HandshakeMessages/ServerClientKeyExchange.o $(SRCDIR)/HandshakeMessages/ServerClientKeyExchange.c
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/TLSConstants.o $(SRCDIR)/TLSConstants.c

recordProtocol: transportProtocol
	@printf "${GREEN}** Make object code for record protocol**${NC}\n"
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/ServerClientRecordProtocol.o $(SRCDIR)/ServerClientRecordProtocol.c

transportProtocol:
	@printf "${GREEN}** Make object code for basic protocol**${NC}\n"
	@mkdir -p $(BUILDDIR)/
	$(CC) $(CFLAGS) $(INC) -c -o $(BUILDDIR)/ServerClientTransportProtocol.o $(SRCDIR)/ServerClientTransportProtocol.c

# Other

clean:
	@printf "${RED}** Clean **${NC}\n"
	@echo " $(RM) -r $(BUILDDIR) $(TARGET)"; $(RM) -r $(BUILDDIR) $(TARGET)
	@echo " $(RM) -r bin"; $(RM) -r bin
