# 컴파일러 설정
CC = gcc
CFLAGS = -g -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1 -I$(HOME)/openssl/include -pthread -I/usr/include
LDFLAGS = -L$(HOME)/openssl/lib -lssl -lcrypto

# 빌드할 대상
TARGET = aes_gcm
SRCS = main.c
OBJS = $(SRCS:.c=.o)

# 기본 빌드 명령
all: $(TARGET)

# 실행 파일 생성
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# 개별 파일 컴파일
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 정리
clean:
	rm -f $(TARGET) $(OBJS)

# 새로 빌드
rebuild: clean all
