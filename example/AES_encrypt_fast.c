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

#include "test_common.h"

typedef struct
{
    unsigned char keystreams[BUFFER_SIZE][AES_GCM_BLOCK_SIZE];
    atomic_int head;
    atomic_int tail;
} CircularBuffer;

CircularBuffer ks_buffer;
unsigned char aes_key[KEY_LENGTH]; 
unsigned char aes_iv[IV_LENGTH];  
EVP_CIPHER_CTX *ctx;            
atomic_bool stop_flag = false; 

int CB_used(int head, int tail, int buf_size) {
    return (tail - head + buf_size) % buf_size;
}

int borim_processKeystream(unsigned char *buf, int len) {
    int cnt = 0, res = len;
    int head_index, item_len, tail_index;
    if (buf == NULL) 
        return -1;

    while (res != 0) {
        while (1) {
            item_len = CB_used(ks_buffer.head, ks_buffer.tail, BUFFER_SIZE);
            if (item_len <= 0) {
            } else {
                head_index = atomic_load(&ks_buffer.head);
                tail_index = atomic_load(&ks_buffer.tail);
                /*
                head_index = ks_buffer.head;
                tail_index = ks_buffer.tail;
                */
                break;
            }
        }

        if (item_len <= res) 
            cnt = item_len;
        else
            cnt = res;

        int space_end = head_index + cnt;

        if (space_end <= BUFFER_SIZE) {
            memcpy(buf, ks_buffer.keystreams[head_index], AES_GCM_BLOCK_SIZE * cnt);
        } else {
            int end = BUFFER_SIZE - head_index;
            int rest = (head_index + cnt) % BUFFER_SIZE;

            memcpy(buf, ks_buffer.keystreams[head_index], AES_GCM_BLOCK_SIZE * end);
            memcpy(buf + (AES_GCM_BLOCK_SIZE * end), ks_buffer.keystreams[0], AES_GCM_BLOCK_SIZE * rest);
        }
        atomic_store(&ks_buffer.head, (head_index + cnt) % BUFFER_SIZE);
        res -= cnt;
        buf += (cnt * AES_GCM_BLOCK_SIZE);

        /*
        ks_buffer.head = (head_index + res) % BUFFER_SIZE;
        */
    }
    return res;
}

void aes_gcm_generate_keystream(unsigned char *keystream, int *block_cnt, int buf_len)
{
    jinho_EVP_EncryptUpdate(ctx, keystream, block_cnt, (const unsigned char *)"A", buf_len);
}


int CB_free_space(CircularBuffer cb) {
    return (cb.head - cb.tail - 1 + BUFFER_SIZE) % BUFFER_SIZE;
}

void print_keystream(FILE *out, unsigned char *keystream, int ctr_start, int len) {
  for (size_t i=0; i<len; i++) {
    unsigned ctr = ctr_start + i;
    fprintf(out, "(CTR = %08d) ", ctr);
    for (size_t j=0; j<16; j++) {
      fprintf(out, "%02x ", keystream[i * 16 + j]);
    }
    fprintf(out, "\n");
  }
}


void *keystream_generator_thread(void *arg)
{
    int block_cnt;
    int tmp_flag = 0;
    while (!stop_flag)
    {
        int free_space =  CB_free_space(ks_buffer);
        if(free_space < CHUNK_SIZE) {
            usleep(WAIT_INTERVAL);
            continue;
        }

        int tail_index = atomic_load(&ks_buffer.tail);
        /*
        int tail_index = ks_buffer.tail;
        */

        int space_end = BUFFER_SIZE - tail_index;
        if (space_end >= CHUNK_SIZE) {
            aes_gcm_generate_keystream(ks_buffer.keystreams[tail_index], &block_cnt, CHUNK_SIZE);
        } else {
            aes_gcm_generate_keystream(ks_buffer.keystreams[tail_index], &block_cnt, space_end);
            aes_gcm_generate_keystream(ks_buffer.keystreams[0], &block_cnt, CHUNK_SIZE - space_end);
        }
        
        /*
        if (tmp_flag <= 3) {
            fprintf(stdout, "Key generation threads\n");
            print_keystream(stdout, ks_buffer.keystreams[ks_buffer.head], 0, ks_buffer.tail);
            fprintf(stdout, "\n");
            tmp_flag++;
        }
        */

        atomic_store(&ks_buffer.tail, (tail_index + CHUNK_SIZE) % BUFFER_SIZE);
        /*
        ks_buffer.tail = (ks_buffer.tail + CHUNK_SIZE) % BUFFER_SIZE;
        */
    }

    return NULL;
}

void *xor_encryption_thread(void *arg)
{
    
    const size_t BLOCK_SIZE = 16;
    size_t plaintext_len = 0;
    unsigned char plaintext[P_BUFFER_SIZE];
    memset(plaintext, 0x00, P_BUFFER_SIZE);
    f_read_contents(PLAINTEXT_FILE, plaintext, P_BUFFER_SIZE);
	plaintext_len = strlen((char *) plaintext);
    unsigned char *out_buf = malloc(plaintext_len + BLOCK_SIZE);
    unsigned char auth_tag[AUTH_TAG_LENGTH];

    unsigned char ks[BUFFER_SIZE][AES_GCM_BLOCK_SIZE];

    FILE *out_file = fopen(FAST_ENC_FILE, "wb");
    if (!out_file)
    {
        fprintf(stderr, "Failed to open ciphertext.bin for writing\n");
        return NULL;
    }

    fwrite(aes_iv, 1, IV_LENGTH, out_file);


    struct timespec start, end;
    double elapsed_time;
    int block_cnt;

    if ((plaintext_len % AES_GCM_BLOCK_SIZE) == 0) 
        block_cnt = plaintext_len / AES_GCM_BLOCK_SIZE;
    else
        block_cnt = plaintext_len / AES_GCM_BLOCK_SIZE + 1;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int repeat = 0; repeat < LOOP_COUNT; repeat++)
    {
	    int out_nbytes = 0;
        borim_processKeystream(ks, block_cnt);

        // fprintf(stdout, "%p\n", ks);
        // print_keystream(stdout, ks, 0, block_cnt);
	    borim_EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, plaintext, plaintext_len, ks, block_cnt);

	    fwrite(out_buf, 1, out_nbytes, out_file);
	    usleep(SLEEP_INTERVAL); 
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;

    printf("Execution time: %.6f seconds\n", elapsed_time);

    stop_flag = true;

    int len;
    EVP_EncryptFinal_ex(ctx, NULL, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LENGTH, auth_tag);
    fwrite(auth_tag, 1, AUTH_TAG_LENGTH, out_file); 

    fclose(out_file);
    return NULL;
}

int main(int argc, char *argv[])
{

    pthread_t ks_thread, xor_thread;

    if (argc != 3 || strlen(argv[1]) != KEY_LENGTH * 2)
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

    unsigned char *iv = OPENSSL_hexstr2buf(argv[2], &decoded_key_len);
    if(!iv || decoded_key_len != IV_LENGTH)
    {
        fprintf(stderr, "Failed to generate IV\n");
        EVP_CIPHER_CTX_free(ctx);
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

    ks_buffer.head = 0;
    ks_buffer.tail = 0;

    pthread_create(&ks_thread, NULL, keystream_generator_thread, NULL);
    pthread_create(&xor_thread, NULL, xor_encryption_thread, NULL);

    pthread_join(xor_thread, NULL);
    pthread_join(ks_thread, NULL);


    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
