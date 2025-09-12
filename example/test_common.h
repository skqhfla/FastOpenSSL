#include <stdio.h>
#include <stdlib.h>

// Common 
#define KEY_LENGTH 32
#define IV_LENGTH 12
#define AUTH_TAG_LENGTH 16
#define LOOP_COUNT 50
#define SLEEP_INTERVAL 10000


#define P_BUFFER_SIZE   65536
#define PLAINTEXT_FILE "plaintext.txt"
#define FAST_ENC_FILE  "encrypt.fast"
#define FAST_DEC_FILE  "decrypt.fast"

#define NORM_ENC_FILE  "encrypt.norm"
#define NORM_DEC_FILE  "decrypt.norm"


// Fast openssl
#define BUFFER_SIZE 8192 
#define AES_GCM_BLOCK_SIZE 16
#define CHUNK_SIZE  16
#define WAIT_INTERVAL   10



int f_read_contents(char *f_name, unsigned char *buffer, int buf_size) {
    long f_size;
    int read_len;
    FILE *fp = fopen(f_name, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to read file: %s\n", f_name);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    f_size = ftell(fp);
    rewind(fp);

    if (f_size < 0 || buf_size <= 0) {
        fprintf(stderr, "Invalid file size or buffer size\n");
        fclose(fp);
        return -1;
    }

    read_len = (buf_size - 1 < f_size) ? (buf_size - 1) : (int)f_size;

    size_t read_size = fread(buffer, 1, read_len, fp);
    buffer[read_size] = '\0';

    fclose(fp);
    return (int)read_size;
}

size_t f_size(char *f_name) {
    FILE *fp = fopen(f_name, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to read file: %s\n", f_name);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fclose(fp);

    return size;
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


int CB_used(int head, int tail, int buf_size) {
    return (tail - head + buf_size) % buf_size;
}

int CB_free_space(int head, int tail, int buf_size) {
    return (head - tail - 1 + buf_size) % buf_size;
}



