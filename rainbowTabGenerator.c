#include <stdio.h>
#include <csv.h>
#include <stdlib.h>
#include <zsv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define DICTIONARY_NAME "dictionary_5000.csv"
#define DICTIONARY_SIZE 5000

int main () {
    
    //apertura in lettura del dizionario
    FILE *dictionary;
    dictionary = fopen(DICTIONARY_NAME, "r"); 

    char* line_buffer = NULL;
    size_t line_buffer_size = 0;

    unsigned char** keys;
    keys = malloc(DICTIONARY_SIZE * sizeof(char*));

    for (int i = 0; i < DICTIONARY_SIZE; i++) {
        keys[i] = malloc(32 * sizeof(unsigned char));

        int chars_read;
        if (((chars_read = getline(&line_buffer, &line_buffer_size, dictionary)) == -1)) {
            printf("Error reading line %d from dictionary\n", i);
            return 1;
        }
        chars_read--;

        PKCS5_PBKDF2_HMAC(
        line_buffer, chars_read, 
        NULL, 0, 
        1000, 
        EVP_sha256(), 
        32, 
        keys[i]
        );
    }

    //debug: stampa delle chiavi generate
    /*
    for(int i = 0; i < DICTIONARY_SIZE; i++) {
            printf("Key %d: ", i);
            for (int j = 0; j < 32; j++) {
                printf("%02x", (unsigned char)keys[i][j]);
            }
            printf("\n");
        }
    */
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    FILE *encrypted_file;
    int file_index = 1;
    char* filename = malloc(36 * sizeof(char)); // "doc_0000.enc" + null terminator
    unsigned char* encrypted_block_buffer = malloc(16 * sizeof(unsigned char)); // AES block size is 16 bytes
    unsigned char* decrypted_block_buffer = malloc(16 * sizeof(unsigned char)); // AES block size is 16 bytes
    snprintf(filename, 36, "./PIRAS/PIRAS_unsalted/doc_%04d.enc", file_index);
    int* decrypted_bytes = malloc(sizeof(int));

    //costante header inizio file
    const char expected_header[16] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a, 0x31};

    printf("About to process files...\n");

    while ((encrypted_file = fopen(filename, "rb"))) {
        printf("Processing file: %s\n", filename);
        for (int i = 0; i < DICTIONARY_SIZE; i++) {
            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keys[i], NULL);
            fread(encrypted_block_buffer, 1, 16, encrypted_file);
            EVP_DecryptUpdate(ctx, decrypted_block_buffer, decrypted_bytes, encrypted_block_buffer, 16);
            if (memcmp(decrypted_block_buffer, expected_header, 16) != 0) {
                rewind(encrypted_file); // Torna all'inizio del file per il prossimo tentativo
                continue; // Chiave non corretta, prova la prossima
            }
            
            FILE *output_file = fopen("decrypted_output.pdf", "wb");
            fwrite(decrypted_block_buffer, 1, 16, output_file); // Scrive il blocco decifrato su output_file

            while(fread(encrypted_block_buffer, 1, 16, encrypted_file) > 0) {
                EVP_DecryptUpdate(ctx, decrypted_block_buffer, decrypted_bytes, encrypted_block_buffer, 16);
                fwrite(decrypted_block_buffer, 1, 16, output_file); // Scrive il blocco decifrato su output_file
            }

            if(EVP_DecryptFinal_ex(ctx, decrypted_block_buffer, NULL)) {
                fclose(encrypted_file);
                fclose(output_file);
                EVP_CIPHER_CTX_free(ctx);
                printf("File %s decrypted successfully with key %d\n", filename, i + 1);
                return 0;
            }

            fclose(output_file);
            remove("decrypted_output.pdf"); // Rimuove il file se la decifratura non è riuscita
            rewind(encrypted_file); // Torna all'inizio del file per il prossimo tentativo
        }
        
        fclose(encrypted_file);
        file_index++;

        snprintf(filename, 36, "./PIRAS/PIRAS_unsalted/doc_%04d.enc", file_index);
    }

    printf("All files processed or error opening files\n");
    
    return 0;
    
    /*
    int char_read;
    if ((char_read = getline(&line_buffer, buffer_size, dictionary))) {
        strtok()
    }
    */
    /*struct csv_parser parser;*/
    /*csv_init(parser, )*/

}