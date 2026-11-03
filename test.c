#include<stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define INPUT_FILE_NAME "test.enc"
#define OUTPUT_FILE_NAME "test.dec"
#define PASSWORD "password"

int main() {
    FILE *input_file = fopen(INPUT_FILE_NAME, "rb");
    FILE *output_file = fopen(OUTPUT_FILE_NAME, "wb");

    if (!input_file || !output_file) {
        fprintf(stderr, "Error opening files\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        return 1;
    }

    unsigned char derived_key_buffer[32];
    PKCS5_PBKDF2_HMAC(
        PASSWORD, strlen(PASSWORD),
        NULL, 0,
        1000,
        EVP_sha256(),
        32,
        derived_key_buffer
        );

    // Initialize decryption
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key_buffer, NULL)) {
        fprintf(stderr, "Error initializing decryption\n");
        return 1;
    }

    int decrypted_bytes;
    int bytes_read;
    unsigned char* encrypted_block_buffer = malloc(16 * sizeof(unsigned char));
    unsigned char* decrypted_block_buffer = malloc(16 * sizeof(unsigned char));
    while((bytes_read = fread(encrypted_block_buffer, 1, 16, input_file)) > 0) {
        if (!EVP_DecryptUpdate(ctx, decrypted_block_buffer, &decrypted_bytes, encrypted_block_buffer, bytes_read)) {
            fprintf(stderr, "Error during decryption\n");
            return 1;
        }
        printf("Decrypted block: %s \n", decrypted_block_buffer);
        fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file);
    }

    if (!EVP_DecryptFinal_ex(ctx, decrypted_block_buffer, &decrypted_bytes)) {
        fprintf(stderr, "Error during final decryption\n");
        return 1;
    }
    fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file);


    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return 0;
}