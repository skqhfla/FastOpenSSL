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
unsigned char aes_iv[IV_LENGTH];       // AES-GCM IV (Nonce)
EVP_CIPHER_CTX *ctx;               // OpenSSL 컨텍스트
atomic_bool stop_flag = false;     // ks_thread 종료 플래그
FILE *keystream_file = NULL;

const char *input_filename = "plaintext";
FILE *input_file = NULL;

// AES-GCM을 사용한 keystream 생성 함수
void aes_gcm_generate_keystream(unsigned char *keystream)
{
    // TODO : AES_Encrypt 함수 호출 후 buffer에 저장하는 코드 필요.
    int len;
    jinho_EVP_EncryptUpdate(ctx, keystream, &len, "A", 1);
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
		fprintf(keystream_file, "\\%03o", ks_buffer.keystreams[ks_buffer.tail][i]);
	fprintf(keystream_file, "\n");
	ks_buffer.tail = next_tail;

    }

    printf("Keystream generator thread exiting...\n");
    return NULL;
}

// XOR 연산 스레드
void *xor_encryption_thread(void *arg)
{
    unsigned char auth_tag[AUTH_TAG_LENGTH];

    FILE *out_file = fopen("encrypt_fast.out", "wb");
    if (!out_file)
    {
        fprintf(stderr, "Failed to open ciphertext.bin for writing\n");
        return NULL;
    }

    fwrite(aes_iv, 1, IV_LENGTH, out_file); // IV 저장 (최초 1회)

    const size_t BUF_SIZE = 64 * 1024;
    const size_t BLOCK_SIZE = 16;
    unsigned char *in_buf = malloc(BUF_SIZE);
    unsigned char *out_buf = malloc(BUF_SIZE + BLOCK_SIZE);

    struct timespec start, end;
    double elapsed_time;

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!feof(input_file)) {
        size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, input_file);

        int out_nbytes = 0;
        borim_EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, in_buf, in_nbytes, &ks_buffer);
        fwrite(out_buf, 1, out_nbytes, out_file);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;

    printf("[AES_encrypt_fast] Execution time: %.6f seconds\n", elapsed_time);

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

    pthread_t ks_thread, xor_thread;

    // 명령행 인자로 AES 키 받기
    if (argc != 3 || strlen(argv[1]) != KEY_LENGTH * 2)
    {
        fprintf(stderr, "Usage: %s <32-byte AES key (64 hex chars)>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    input_file = fopen(input_filename, "rb");

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

    /*
    // IV (Nonce) 생성
    if (RAND_bytes(iv, IV_LENGTH) != 1)
    {
        fprintf(stderr, "Failed to generate IV\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    */

    unsigned char *iv = OPENSSL_hexstr2buf(argv[2], &decoded_key_len);
    if (!iv || decoded_key_len != IV_LENGTH)
    {
        fprintf(stderr, "Invalid AES iv! Must be %d bytes (64 hex chars).\n", IV_LENGTH);
        exit(EXIT_FAILURE);
    }
    memcpy(aes_iv, iv, IV_LENGTH);
    OPENSSL_free(iv);


    // AES-GCM 모드 설정

    if (!jinho_EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, aes_iv))
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


    // OpenSSL Context 해제
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
