#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#define KEY_LENGTH 	32
#define IV_LENGTH 	12
const size_t AUTH_TAG_LENGTH = 16;
unsigned char aes_iv[IV_LENGTH];       // AES-GCM IV (Nonce)
const char *input_filename = "plaintext";

FILE *input_file = NULL;

int encrypt(FILE* out_file, const unsigned char* key, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* out_file = NULL;
    unsigned char* key = NULL;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s INPUT_FILE OUTPUT_FILE KEY_HEX\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* key_hex   = argv[1];

    long decoded_key_len = 0;
    key = OPENSSL_hexstr2buf(key_hex, &decoded_key_len);
    if (!key || decoded_key_len != KEY_LENGTH) {
        fprintf(stderr, "Wrong key \"%s\", must be %lu hex digits\n", key_hex, KEY_LENGTH * 2);
        goto failure;
    }

    unsigned char *iv = OPENSSL_hexstr2buf(argv[2], &decoded_key_len);
    if (!iv || decoded_key_len != IV_LENGTH)
    {
        fprintf(stderr, "Invalid AES iv! Must be %d bytes (64 hex chars).\n", IV_LENGTH);
        exit(EXIT_FAILURE);
    }
    memcpy(aes_iv, iv, IV_LENGTH);
    OPENSSL_free(iv);


    out_file = fopen("encrypt.out", "wb");
    if (!out_file) {
        fprintf(stderr, "Could not open output file \n");
        goto failure;
    }

    int err = encrypt(out_file, key, stderr);
    if (err) {
        fprintf(stderr, "Encryption failed\n");
        goto failure;
    }

    fprintf(stderr, "Encryption succeeded\n");
    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    OPENSSL_free(key);
    if (out_file)
        fclose(out_file);

    return exit_code;
}

int encrypt(FILE* out_file, const unsigned char* key, FILE* error_stream) {
    int exit_code = 0;

    EVP_CIPHER_CTX* ctx = NULL;

    unsigned char auth_tag[AUTH_TAG_LENGTH];

    const size_t BUF_SIZE = 64 * 1024;
    const size_t BLOCK_SIZE = 16;
    unsigned char* in_buf  = malloc(BUF_SIZE);
    unsigned char* out_buf = malloc(BUF_SIZE + BLOCK_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, aes_iv);
    
    fwrite(aes_iv, 1, IV_LENGTH, out_file);

    struct timespec start, end;
    double elapsed_time;
    
    input_file = fopen(input_filename, "rb");

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!feof(input_file)) {
        size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, input_file);

        int out_nbytes = 0;
        EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, in_buf, in_nbytes);
        fwrite(out_buf, 1, out_nbytes, out_file);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;

    printf("[AES_encrypt] Execution time: %.6f seconds\n", elapsed_time);

    int out_nbytes = 0;
    EVP_EncryptFinal(ctx, out_buf, &out_nbytes);
    fwrite(out_buf, 1, out_nbytes, out_file);

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LENGTH, auth_tag);
    fwrite(auth_tag, 1, AUTH_TAG_LENGTH, out_file);
    
    //

    if (ferror(out_file)) {
        if (error_stream)
            fprintf(error_stream, "I/O error\n");
        goto failure;
    }

    if (!ok) {
        if (error_stream)
            fprintf(error_stream, "Encryption error\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    free(out_buf);
    free(in_buf);

    return exit_code;
}

