#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#define BUFFER_SIZE 256 // Circular buffer 크기
#define IV_LENGTH 12
#define KEY_LENGTH 32
#define AES_GCM_BLOCK_SIZE 16 // Keystream 블록 크기
#define AUTH_TAG_LENGTH 16

typedef struct
{
    unsigned char keystreams[BUFFER_SIZE][AES_GCM_BLOCK_SIZE];
    atomic_int head;
    atomic_int tail;
} CircularBuffer;

CircularBuffer ks_buffer;
unsigned char aes_key[KEY_LENGTH]; // AES 256-bit 키
unsigned char iv[IV_LENGTH];       // AES-GCM IV (Nonce)
EVP_CIPHER_CTX *ctx;               // OpenSSL 컨텍스트
atomic_bool stop_flag = false;     // ks_thread 종료 플래그
FILE *keystream_file = NULL;

// AES-GCM을 사용한 keystream 생성 함수
void aes_gcm_generate_keystream(unsigned char *keystream)
{
    // TODO : AES_Encrypt 함수 호출 후 buffer에 저장하는 코드 필요.
    int len;
    jinho_EVP_EncryptUpdate(ctx, keystream, &len, "A", 1, NULL);
}

// Keystream 생성 스레드
void *keystream_generator_thread(void *arg)
{
    keystream_file = fopen("./keystream.log", "w");
    while (!stop_flag) // 🔹 종료 플래그를 확인하여 루프 탈출
    {
        int next_tail = (ks_buffer.tail + 1) % BUFFER_SIZE;
        if (next_tail == ks_buffer.head)
        {
            usleep(1000); // 버퍼가 가득 차면 대기
            continue;
        }

        aes_gcm_generate_keystream(ks_buffer.keystreams[ks_buffer.tail]);
	for (int i=0; i<16; i++) 
		fprintf(keystream_file, "%02x", ks_buffer.keystreams[ks_buffer.tail][i]);
	fprintf(keystream_file, "\n");
	ks_buffer.tail = next_tail;

    }

    printf("Keystream generator thread exiting...\n");
    return NULL;
}

// XOR 연산 스레드
void *xor_encryption_thread(void *arg)
{
    unsigned char plaintext[] = "1234567890\0";
    size_t plaintext_len = strlen((char *)plaintext);
    unsigned char ciphertext[AES_GCM_BLOCK_SIZE];
    unsigned char auth_tag[AUTH_TAG_LENGTH];

    FILE *out_file = fopen("ciphertext.bin", "wb");
    if (!out_file)
    {
        fprintf(stderr, "Failed to open ciphertext.bin for writing\n");
        return NULL;
    }

    fwrite(iv, 1, IV_LENGTH, out_file); // IV 저장 (최초 1회)

    const size_t BUF_SIZE = 64 * 1024;
    const size_t BLOCK_SIZE = 16;
    unsigned char *in_buf = malloc(BUF_SIZE);
    unsigned char *out_buf = malloc(BUF_SIZE + BLOCK_SIZE);

    for (int repeat = 0; repeat < 5; repeat++)
    {
        size_t offset = 0;
        while (offset < plaintext_len)
        {
	    int out_nbytes = 0;
            jinho_EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, plaintext, plaintext_len, &ks_buffer);

            if (fwrite(out_buf, 1, out_nbytes, out_file) != out_nbytes)
            {
                fprintf(stderr, "Error writing ciphertext to file\n");
            }

            printf("Block %zu saved to ciphertext.bin\n", offset / AES_GCM_BLOCK_SIZE);
            offset += out_nbytes;
        }

        usleep(10000); // 10ms 대기
    }

    stop_flag = true;

    int len;
    EVP_EncryptFinal_ex(ctx, NULL, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LENGTH, auth_tag);
    fwrite(auth_tag, 1, AUTH_TAG_LENGTH, out_file); // 인증 태그 저장

    fclose(out_file);
    return NULL;
}

int main(int argc, char *argv[])
{
    struct timespec start, end;
    double elapsed_time;

    // 시작 시간 기록
    clock_gettime(CLOCK_MONOTONIC, &start);

    pthread_t ks_thread, xor_thread;

    // 명령행 인자로 AES 키 받기
    if (argc != 2 || strlen(argv[1]) != KEY_LENGTH * 2)
    {
        fprintf(stderr, "Usage: %s <32-byte AES key (64 hex chars)>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    long decoded_key_len = 0;
    unsigned char *key = OPENSSL_hexstr2buf(argv[1], &decoded_key_len);
    if (!key || decoded_key_len != KEY_LENGTH)
    {
        fprintf(stderr, "Invalid AES key! Must be %d bytes (64 hex chars).\n", KEY_LENGTH);
        exit(EXIT_FAILURE);
    }
    memcpy(aes_key, key, KEY_LENGTH);
    OPENSSL_free(key);

    // OpenSSL Context 초기화
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Failed to create OpenSSL context\n");
        exit(EXIT_FAILURE);
    }

    // IV (Nonce) 생성
    if (RAND_bytes(iv, IV_LENGTH) != 1)
    {
        fprintf(stderr, "Failed to generate IV\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // AES-GCM 모드 설정
    printf("Encrypt IV: %s\n", iv);
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv))
    {
        fprintf(stderr, "Failed to initialize AES-GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Circular buffer 초기화
    ks_buffer.head = 0;
    ks_buffer.tail = 0;

    // 스레드 생성
    pthread_create(&ks_thread, NULL, keystream_generator_thread, NULL);
    pthread_create(&xor_thread, NULL, xor_encryption_thread, NULL);

    // 🔹 `xor_thread` 종료 후 `ks_thread` 강제 종료 대기
    pthread_join(xor_thread, NULL);
    pthread_join(ks_thread, NULL);

    // 종료 시간 기록
    clock_gettime(CLOCK_MONOTONIC, &end);

    // 경과 시간 계산 (초 단위 변환)
    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;

    printf("Execution time: %.6f seconds\n", elapsed_time);

    // OpenSSL Context 해제
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
