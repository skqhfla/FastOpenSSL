#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "test_common.h"

typedef struct
{
    unsigned char keystreams[BUFFER_SIZE][AES_GCM_BLOCK_SIZE];
    atomic_int head;
    atomic_int tail;
} CircularBuffer;

CircularBuffer ks_buffer;
unsigned char aes_key[KEY_LENGTH]; 
unsigned char iv[IV_LENGTH];      
EVP_CIPHER_CTX *ctx;             
atomic_bool stop_flag = false;

void aes_gcm_generate_keystream(unsigned char *keystream, int *block_cnt, int buf_len)
{
    jinho_EVP_EncryptUpdate(ctx, keystream, block_cnt, (const unsigned char *)"A", buf_len);
}

int CB_free_space(CircularBuffer cb) {
    return (cb.head - cb.tail - 1 + BUFFER_SIZE) % BUFFER_SIZE;
}


void *keystream_generator_thread(void *arg)
{
    int block_cnt;
    while (!stop_flag)
    {
        int free_space = CB_free_space(ks_buffer);
        if(free_space < CHUNK_SIZE) {
            usleep(WAIT_INTERVAL);
            continue;
        }

        /*
        int tail_index = atomic_load(&ks_buffer.tail);
        */
        int tail_index = ks_buffer.tail;

        int space_end = BUFFER_SIZE - ks_buffer.tail;
        if (space_end >= CHUNK_SIZE) {
            aes_gcm_generate_keystream(ks_buffer.keystreams[tail_index], &block_cnt, CHUNK_SIZE);
        } else {
            aes_gcm_generate_keystream(ks_buffer.keystreams[tail_index], &block_cnt, space_end);
            aes_gcm_generate_keystream(ks_buffer.keystreams[0], &block_cnt, CHUNK_SIZE - space_end);
        }

        /*
        atomic_store(&ks_buffer.tail, (tail_index + CHUNK_SIZE) % BUFFER_SIZE);
         */
        ks_buffer.tail = (ks_buffer.tail + CHUNK_SIZE) % BUFFER_SIZE;
    }

    return NULL;
}


void *xor_encryption_thread(void *arg)
{
    FILE *in_file = NULL;
    FILE *out_file = NULL;

    struct stat in_file_stat;
    int err = stat(FAST_ENC_FILE, &in_file_stat);
    if (err)
    {
        fprintf(stderr, "Could not stat input file \"%s\"\n", FAST_ENC_FILE);
        return NULL;
    }

    size_t in_file_size = in_file_stat.st_size;
    if (in_file_size < IV_LENGTH + AUTH_TAG_LENGTH)
    {
        fprintf(stderr, "Input file \"%s\" is too short\n", FAST_ENC_FILE);
        return NULL;
    }

    in_file = fopen(FAST_ENC_FILE, "rb");
    if (!in_file)
    {
        fprintf(stderr, "Could not open input file \"%s\"\n", FAST_ENC_FILE);
        return NULL;
    }

    out_file = fopen(FAST_DEC_FILE, "wb");
    if (!out_file)
    {
        fprintf(stderr, "Could not open output file \"%s\"\n", FAST_DEC_FILE);
        return NULL;
    }

    unsigned char auth_tag[AUTH_TAG_LENGTH];
    unsigned char* in_buf  = malloc(P_BUFFER_SIZE);
    unsigned char* out_buf = malloc(P_BUFFER_SIZE);

    int in_nbytes = fread(iv, 1, IV_LENGTH, in_file);

    size_t read_size = f_size(PLAINTEXT_FILE);
    size_t auth_tag_pos = in_file_size - AUTH_TAG_LENGTH;
    size_t current_pos = in_nbytes;

    struct timespec start, end;
    double elapsed_time;

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (current_pos < auth_tag_pos) {
        size_t in_nbytes_left = auth_tag_pos - current_pos;
        size_t in_nbytes_wanted = in_nbytes_left < read_size ? in_nbytes_left : read_size;

        in_nbytes = fread(in_buf, 1, in_nbytes_wanted, in_file);
        current_pos += in_nbytes;

        int out_nbytes = 0;
        borim_EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, in_buf, in_nbytes, &ks_buffer);
        fwrite(out_buf, 1, out_nbytes, out_file);
        usleep(SLEEP_INTERVAL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;

    printf("Execution time: %.6f seconds\n", elapsed_time);

    stop_flag = true;

    in_nbytes = fread(auth_tag, 1, AUTH_TAG_LENGTH, in_file);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LENGTH, auth_tag);

    int out_nbytes = 0;
    int ok = EVP_DecryptFinal(ctx, out_buf, &out_nbytes);
    fwrite(out_buf, 1, out_nbytes, out_file);

    if (!ok)
    {
        fprintf(stdout, "Decryption error\n");
    }
    fprintf(stderr, "Decryption succeeded\n");

    fclose(out_file);
    fclose(in_file);
    return NULL;
}

int main(int argc, char *argv[])
{

    pthread_t ks_thread, xor_thread;

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

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Failed to create OpenSSL context\n");
        exit(EXIT_FAILURE);
    }

    FILE *in_file = NULL;

    struct stat in_file_stat;
    int err = stat(FAST_ENC_FILE, &in_file_stat);
    if (err)
    {
        fprintf(stderr, "Could not stat input file \"%s\"\n", FAST_ENC_FILE);
        return -1;
    }

    size_t in_file_size = in_file_stat.st_size;
    if (in_file_size < IV_LENGTH + AUTH_TAG_LENGTH)
    {
        fprintf(stderr, "Input file \"%s\" is too short\n", FAST_ENC_FILE);
        return -1;
    }

    in_file = fopen(FAST_ENC_FILE, "rb");
    if (!in_file)
    {
        fprintf(stderr, "Could not open input file \"%s\"\n", FAST_ENC_FILE);
        return -1;
    }

    int in_nbytes = fread(iv, 1, IV_LENGTH, in_file);
    if(in_nbytes != IV_LENGTH){
        fprintf(stderr, "Failed to read IV\n");
        exit(EXIT_FAILURE);
    }

    fclose(in_file);

    // AES-GCM 모드 설정
    if (!jinho_EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv))
    {
        fprintf(stderr, "Failed to initialize AES-GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    ks_buffer.head = 0;
    ks_buffer.tail = 0;

    pthread_create(&ks_thread, NULL, keystream_generator_thread, NULL);
    pthread_create(&xor_thread, NULL, xor_encryption_thread, NULL);

    pthread_join(xor_thread, NULL);
    pthread_join(ks_thread, NULL);


    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
