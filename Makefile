CC := gcc # This is the main compiler
#CC := clang --analyze # and comment out the linker last line for sanity
SRCDIR := src
BUILDDIR := build
TARGET := test/clientBasic

SRCEXT := c
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
CFLAGS := -g -Wall -lpthread -std=gnu99 -pthread -O3
INC := -I include

GREEN=\033[0;32m
RED=\033[0;31m
NC=\033[0m # No Color


all: testBasic testRecord testHandshake
.PHONY : all

# Tests
testHandshake: TEST_NAME=Handshake
testHandshake: $(OBJECTS)
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) $^ tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME)
	$(CC) $(CFLAGS) $^ tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME)

testRecord: TEST_NAME=Record
testRecord: $(OBJECTS)
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) $^ tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME)
	$(CC) $(CFLAGS) $^ tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME)

testBasic: TEST_NAME=Basic
testBasic: $(OBJECTS)
	@printf "${GREEN}** Make test for $(TEST_NAME) **${NC}\n"
	@mkdir -p bin/test$(TEST_NAME)
	$(CC) $(CFLAGS) $^ tests/client$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/client$(TEST_NAME)
	$(CC) $(CFLAGS) $^ tests/server$(TEST_NAME).c $(INC) -o bin/test$(TEST_NAME)/server$(TEST_NAME)

#Objects files
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@printf "${GREEN}** Make object code **${NC}\n"
	@mkdir -p $(BUILDDIR)/HandshakeMessages
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"; $(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	@printf "${RED}** Clean **${NC}\n"
	@echo " $(RM) -r $(BUILDDIR) $(TARGET)"; $(RM) -r $(BUILDDIR) $(TARGET)
	@echo " $(RM) -r bin"; $(RM) -r bin
