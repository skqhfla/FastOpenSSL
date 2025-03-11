CFLAGS  += -g -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1 -I$(HOME)/openssl_build/include
LDFLAGS += -L$(HOME)/openssl_build/lib
LDLIBS  += -lssl -lcrypto

C_FILES := $(wildcard *.c)
EXECUTABLES := $(C_FILES:.c=)

default: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
