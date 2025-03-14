CFLAGS  += -g -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1 -I$(HOME)/FastOpenSSL/openssl/include
LDFLAGS += -L$(HOME)/FastOpenSSL/openssl
LDLIBS  += -lssl -lcrypto

C_FILES := $(wildcard *.c)
EXECUTABLES := $(C_FILES:.c=)

default: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
