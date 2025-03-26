CFLAGS  += -g -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1 -I../openssl/include
LDFLAGS += -L../openssl
LDLIBS  += -lssl -lcrypto

C_FILES := $(wildcard *.c)
EXECUTABLES := $(C_FILES:.c=)

default: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
