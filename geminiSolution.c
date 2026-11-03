#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        if (input_file) fclose(input_file);
        if (output_file) fclose(output_file);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    unsigned char derived_key_buffer[48];
    PKCS5_PBKDF2_HMAC(
        PASSWORD, strlen(PASSWORD),
        NULL, 0,
        1000,
        EVP_sha256(),
        48,
        derived_key_buffer
    );
    unsigned char *key = derived_key_buffer; // First 32 bytes for the key
    unsigned char *iv = derived_key_buffer + 32; // Next 16 bytes for the IV

    // Initialize decryption (NULL IV implies all-zero IV; ensure this matches encryption)
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    int decrypted_bytes = 0;
    int bytes_read = 0;
    unsigned char encrypted_block_buffer[16];
    unsigned char decrypted_block_buffer[32]; // slightly larger buffer to safely accommodate block size + padding

    int success = 1;
    while ((bytes_read = fread(encrypted_block_buffer, 1, sizeof(encrypted_block_buffer), input_file)) > 0) {
        if (!EVP_DecryptUpdate(ctx, decrypted_block_buffer, &decrypted_bytes, encrypted_block_buffer, bytes_read)) {
            fprintf(stderr, "Error during decryption update\n");
            success = 0;
            break;
        }
        fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file);
    }

    if (success) {
        if (!EVP_DecryptFinal_ex(ctx, decrypted_block_buffer, &decrypted_bytes)) {
            fprintf(stderr, "Error during decryption finalization (incorrect password or corrupted data)\n");
            success = 0;
        } else {
            fwrite(decrypted_block_buffer, 1, decrypted_bytes, output_file);
        }
    }

    // Cleanup resources
    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return success ? 0 : 1;
}